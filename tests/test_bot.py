import unittest
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

import settings
from bot import main as bot


class TelegramResponseTests(unittest.TestCase):
    def test_success_without_result_is_a_recoverable_error(self):
        with patch.object(bot, 'request', return_value={'ok': True}), self.assertRaises(bot.RequestFailed):
            bot.telegram('getUpdates')


class BotFlowTests(unittest.TestCase):
    def setUp(self):
        self.profile = {'id':12, 'status':'active', 'node':'wg-eu', 'server':'🇩🇪 Германия',
                        'expires':1900000000, 'config_available':False}
        self.state = {'profile':self.profile, 'mode':'live', 'hours':24,
                      'nodes':[{'id':f'n{i}', 'name':f'Server {i}'} for i in range(16)]}
        self.telemetry = patch.object(bot, 'record_interaction').start()
        self.api = patch.object(bot, 'api', return_value=self.state).start()
        self.tg = patch.object(bot, 'telegram', return_value=True).start()
        self.config = patch.multiple(settings, MODE='live', PUBLIC_URL='https://example.test').start()
        self.addCleanup(patch.stopall)

    def callback(self, action):
        return {'callback_query':{'id':'callback', 'from':{'id':1}, 'data':action,
                'message':{'chat':{'id':1, 'type':'private'}, 'message_id':7}}}

    def test_callback_edits_existing_message(self):
        bot.handle(self.callback('status'))
        self.assertEqual(self.tg.call_args.args[0], 'editMessageText')
        self.assertEqual(self.tg.call_args.args[1]['message_id'], 7)

    def test_servers_are_paginated(self):
        bot.handle(self.callback('servers:1'))
        payload = self.tg.call_args.args[1]
        rows = payload['reply_markup']['inline_keyboard']
        self.assertEqual(sum(b['callback_data'].startswith('d:select:') for row in rows for b in row), 8)
        self.assertIn('2/2', payload['text'])

    def test_selection_only_opens_confirmation(self):
        bot.handle(self.callback('select:n1'))
        self.api.assert_called_once_with(1, 'status', scope='device')
        payload = self.tg.call_args.args[1]
        self.assertEqual(payload['reply_markup']['inline_keyboard'][0][0]['callback_data'], 'd:issue:n1:12:a')

    def test_confirmation_sends_expected_profile(self):
        self.api.return_value = self.profile
        bot.handle(self.callback('d:issue:n1:12:a'))
        self.api.assert_called_once_with(1, 'issue', {'node':'n1', 'expected_profile':12, 'expected_status':'active'}, scope='device')

    def test_old_revoke_button_does_not_mutate(self):
        bot.handle(self.callback('revoke'))
        self.api.assert_called_once_with(1, 'status', scope='device')

    def test_revoke_confirmation_is_bound_to_profile(self):
        self.api.return_value = self.profile
        bot.handle(self.callback('d:revoke:12:a'))
        self.api.assert_called_once_with(1, 'revoke', {'expected_profile':12, 'expected_status':'active'}, scope='device')


    def test_unchanged_edit_does_not_send_duplicate(self):
        self.tg.side_effect = bot.RequestFailed('Bad Request: message is not modified')
        bot.send(1, 'Text', message_id=7)
        self.assertEqual(self.tg.call_count, 1)

    def test_dynamic_html_is_escaped(self):
        self.profile['server'] = '<unsafe&server>'
        bot.profile_message(1, self.profile, 'live')
        self.assertIn('&lt;unsafe&amp;server&gt;', self.tg.call_args.args[1]['text'])

    def test_legacy_confirmation_reopens_selection(self):
        bot.handle(self.callback('issue:n1:12'))
        self.api.assert_called_once_with(1, 'status', scope='device')
        self.assertEqual(self.tg.call_args.args[1]['reply_markup']['inline_keyboard'][0][0]['callback_data'], 'd:issue:n1:12:a')

    def test_old_version_revoke_does_not_mutate(self):
        bot.handle(self.callback('revoke:12'))
        self.api.assert_called_once_with(1, 'status', scope='device')

    def test_pending_creation_cannot_be_changed_from_server_picker(self):
        self.profile['status'] = 'creating'
        bot.handle(self.callback('select:n1'))
        self.api.assert_called_once_with(1, 'status', scope='device')
        self.assertIn('Создаётся', self.tg.call_args.args[1]['text'])
        buttons = self.tg.call_args.args[1]['reply_markup']['inline_keyboard']
        self.assertFalse(any(b.get('callback_data', '').startswith('issue:') for row in buttons for b in row))

    def test_telegram_mutation_carries_its_mode(self):
        self.api.return_value = {**self.profile, 'scope':'telegram'}
        bot.handle(self.callback('t:issue:tg-eu:12:a'))
        self.api.assert_called_once_with(1, 'issue', {'node':'tg-eu', 'expected_profile':12, 'expected_status':'active'}, scope='telegram')
        buttons = self.tg.call_args.args[1]['reply_markup']['inline_keyboard']
        self.assertTrue(all(b['callback_data'].startswith('t:') for row in buttons for b in row))

    def test_root_menu_offers_both_modes(self):
        bot.handle(self.callback('menu'))
        rows = self.tg.call_args.args[1]['reply_markup']['inline_keyboard']
        values = [b.get('callback_data') for row in rows for b in row]
        self.assertIn('d:home', values)
        self.assertIn('t:home', values)

    def test_start_installs_persistent_command_buttons(self):
        bot.handle({'message': {'from': {'id': 1}, 'chat': {'id': 1, 'type': 'private'}, 'text': '/start'}})
        keyboard = self.tg.call_args.args[1]['reply_markup']
        self.assertTrue(keyboard['is_persistent'])
        self.assertTrue(keyboard['resize_keyboard'])
        commands = {bot.COMMAND_BUTTONS[item['text']] for row in keyboard['keyboard'] for item in row}
        self.assertTrue({'/start','/app','/servers','/status','/device','/telegram','/config','/revoke','/help','/id','/sticker'} <= commands)

    def test_keyboard_routes_labels_as_complete_commands(self):
        for label, command in bot.COMMAND_BUTTONS.items():
            with self.subTest(label=label), patch.object(bot, 'menu'), patch.object(bot, 'scope_menu'), patch.object(bot.STICKERS, 'submit'):
                self.telemetry.reset_mock()
                bot.handle({'message': {'from': {'id': 1}, 'chat': {'id': 1, 'type': 'private'}, 'text': label}})
                self.telemetry.assert_called_once_with(1, command, 'device')

    def test_revoke_keyboard_button_still_requires_profile_confirmation(self):
        bot.handle({'message': {'from': {'id': 1}, 'chat': {'id': 1, 'type': 'private'}, 'text': '⛔ Отключить профиль'}})
        self.api.assert_not_called()
        rows = self.tg.call_args.args[1]['reply_markup']['inline_keyboard']
        self.assertEqual(rows[0][0]['callback_data'], 'd:confirm-revoke')
        self.assertEqual(rows[1][0]['callback_data'], 't:confirm-revoke')

    def test_admin_keyboard_button_is_visible_only_to_administrators(self):
        for admin in (False, True):
            with self.subTest(admin=admin), patch.object(bot, 'is_admin', return_value=admin):
                labels = {item['text'] for row in bot.command_keyboard(1)['keyboard'] for item in row}
                self.assertEqual('🔧 Админка' in labels, admin)

    def test_live_profile_message_is_compact_and_has_no_expiry(self):
        self.profile.update(expires=0,unlimited=True,config_available=True)
        bot.profile_message(1,self.profile,'live')
        payload=self.tg.call_args.args[1]
        self.assertLess(len(payload['text']),150)
        self.assertIn('Бессрочно',payload['text']); self.assertNotIn('Доступ до',payload['text'])
        rows=payload['reply_markup']['inline_keyboard']
        self.assertEqual(len(rows),3); self.assertEqual(rows[0][1]['callback_data'],'d:export')

    def test_keyboard_is_four_rows_with_all_commands(self):
        with patch.object(bot,'is_admin',return_value=True):keyboard=bot.command_keyboard(1)['keyboard']
        self.assertEqual(len(keyboard),4); self.assertTrue(all(len(row)==3 for row in keyboard))

    def test_telegram_help_has_platform_selection_and_no_vpn_claim(self):
        bot.handle(self.callback('t:guide:ios'))
        self.api.assert_not_called()
        payload = self.tg.call_args.args[1]
        self.assertIn('iPhone / iPad', payload['text'])
        self.assertIn('Прокси действует только в Telegram', payload['text'])

    def test_callbacks_fit_telegram_limit(self):
        self.state['nodes'] = [{'id':'n'*30, 'name':'Server'}]
        self.profile['id'] = 9223372036854775807
        bot.select_server(1,1,'n'*30,scope='telegram')
        rows = self.tg.call_args.args[1]['reply_markup']['inline_keyboard']
        self.assertTrue(all(len(b['callback_data'].encode()) <= 64 for row in rows for b in row))


class StickerDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cache = Path(self.temp.name) / 'sticker.json'
        self.sender = bot.StickerSender(self.cache)

    def test_file_is_uploaded_once_and_reused_after_restart(self):
        with patch.object(settings, 'TOKEN', 'test-token'), patch.object(bot, 'upload', return_value={'sticker': {'file_id': 'cached-sticker'}}) as upload, patch.object(bot, 'telegram') as telegram:
            self.sender._send(1)
            bot.StickerSender(self.cache)._send(2)
        upload.assert_called_once()
        self.assertEqual(upload.call_args.kwargs['timeout'], 10)
        telegram.assert_called_once_with('sendSticker', {'chat_id': 2, 'sticker': 'cached-sticker'}, timeout=10)

    def test_another_bot_cannot_reuse_the_cached_file_id(self):
        with patch.object(settings, 'TOKEN', 'first-token'), patch.object(bot, 'upload', return_value={'sticker': {'file_id': 'old-id'}}):
            self.sender._send(1)
        with patch.object(settings, 'TOKEN', 'new-token'), patch.object(bot, 'upload') as upload, patch.object(bot, 'telegram') as telegram:
            self.sender._send(1)
        upload.assert_called_once()
        telegram.assert_not_called()

    def test_invalid_file_id_is_replaced_with_a_new_upload(self):
        with patch.object(bot, 'upload', return_value={'sticker': {'file_id': 'old-id'}}):
            self.sender._send(1)
        with patch.object(bot, 'telegram', side_effect=bot.RequestFailed('Bad Request: wrong file identifier')), patch.object(bot, 'upload', return_value={'sticker': {'file_id': 'new-id'}}) as upload:
            self.sender._send(1)
        upload.assert_called_once()

    def test_network_failure_does_not_retry_and_send_a_duplicate(self):
        with patch.object(bot, 'upload', return_value={'sticker': {'file_id': 'cached-id'}}):
            self.sender._send(1)
        with patch.object(bot, 'telegram', side_effect=bot.RequestFailed('Нет связи с сервером.')), patch.object(bot, 'upload') as upload:
            with self.assertRaises(bot.RequestFailed):
                self.sender._send(1)
        upload.assert_not_called()

    def test_slow_sticker_does_not_block_commands_or_queue_duplicates(self):
        started, release, finished = threading.Event(), threading.Event(), threading.Event()
        def slow_send(chat):
            started.set()
            release.wait(3)
        def tracked_run():
            try:
                original_run()
            finally:
                finished.set()
        original_run = self.sender._run
        with patch.object(bot, 'STICKERS', self.sender), patch.object(self.sender, '_send', side_effect=slow_send) as delivery, patch.object(self.sender, '_run', side_effect=tracked_run), patch.object(bot, 'record_interaction'), patch.object(bot, 'telegram') as telegram:
            try:
                bot.handle({'message': {'from': {'id': 1}, 'chat': {'id': 1, 'type': 'private'}, 'text': '/sticker'}})
                self.assertTrue(started.wait(1))
                self.assertFalse(self.sender.submit(1))
                bot.handle({'message': {'from': {'id': 1}, 'chat': {'id': 1, 'type': 'private'}, 'text': '/id'}})
                self.assertIn('Ваш Telegram ID', telegram.call_args.args[1]['text'])
                self.assertFalse(finished.is_set())
            finally:
                release.set()
                self.assertTrue(finished.wait(2))
        delivery.assert_called_once_with(1)
        self.assertFalse(self.sender.pending)

    def test_delivery_error_does_not_stop_the_next_job(self):
        with patch.object(bot.threading, 'Thread'):
            self.sender.submit(1)
            self.sender.submit(2)
        with patch.object(self.sender, '_send', side_effect=[OSError('missing file'), None]) as delivery, patch.object(bot, 'telegram'), patch('builtins.print'):
            self.sender._run()
        self.assertEqual(delivery.call_count, 2)
        self.assertFalse(self.sender.pending)
        self.assertIsNone(self.sender.worker)


class BotTelemetryTests(unittest.TestCase):
    def test_unknown_message_text_is_not_recorded(self):
        with patch.object(bot,'api') as api:
            bot.record_interaction(1,'private text with secrets','device')
        api.assert_called_once_with(1,'telemetry',{'action':'chat/message'},scope='device',timeout=2)

    def test_command_records_only_its_known_action(self):
        with patch.object(bot,'api') as api:
            bot.record_interaction(1,'issue:tg-eu:123:a','telegram')
        api.assert_called_once_with(1,'telemetry',{'action':'chat/issue'},scope='telegram',timeout=2)

    def test_audit_failure_does_not_break_local_help(self):
        with patch.object(bot,'api',side_effect=bot.RequestFailed('offline')),patch('builtins.print'):
            bot.record_interaction(1,'/help','device')


class AppLinkTests(unittest.TestCase):
    def test_menu_and_inline_links_use_current_url(self):
        with patch.object(settings,'PUBLIC_URL','https://current.example'),patch.object(bot,'telegram') as telegram:
            bot.refresh_app_menu(123456789)
            payload=telegram.call_args.args[1]
            self.assertEqual(payload['chat_id'],123456789)
            self.assertEqual(payload['menu_button']['web_app']['url'],bot.app_rows()[0][0]['web_app']['url'])

    def test_scope_and_admin_links_preserve_base_query(self):
        with patch.object(settings,'PUBLIC_URL','https://current.example/?existing=yes'):
            from urllib.parse import urlsplit,parse_qs
            url=urlsplit(bot.app_url('telegram'))
            self.assertEqual(parse_qs(url.query)['scope'],['telegram'])
            self.assertEqual(parse_qs(url.query)['existing'],['yes'])
            self.assertEqual(urlsplit(bot.app_url(admin=True)).path,'/admin')

    def test_personal_menu_failure_does_not_break_command(self):
        with patch.object(bot,'telegram',side_effect=bot.RequestFailed('chat unavailable')),patch('builtins.print'):
            bot.refresh_chat_menu(1)


class PersonalAdminMenuTests(unittest.TestCase):
    def test_admin_startup_menu_opens_admin_on_current_host(self):
        with patch.multiple(settings,PUBLIC_URL='https://current.example',ADMIN_IDS='123456789'),patch.object(bot,'telegram') as telegram:
            bot.configure_bot()
        menus=[call.args[1] for call in telegram.call_args_list if call.args[0]=='setChatMenuButton']
        personal=next(item for item in menus if item.get('chat_id')==123456789)
        self.assertEqual(personal['menu_button']['text'],'Админка')
        self.assertIn('https://current.example/admin',personal['menu_button']['web_app']['url'])

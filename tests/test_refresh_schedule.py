from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
import threading
import subprocess
from unittest.mock import patch

from backend import refresh_schedule as schedule
from backend import local_maintenance


class StopSchedule(Exception):
    pass


class ScheduleTests(unittest.TestCase):
    def test_scans_start_hourly_without_adding_the_scan_duration(self):
        now=[0]; starts=[]; sleeps=[]
        def job():
            starts.append(now[0]); now[0]+=90
        def sleep(seconds):
            sleeps.append(seconds); now[0]+=seconds
            if len(sleeps)==3:raise StopSchedule
        with patch.object(schedule.time,'monotonic',side_effect=lambda:now[0]),patch.object(schedule.time,'sleep',side_effect=sleep):
            with self.assertRaises(StopSchedule):schedule.hourly(job)
        self.assertEqual(starts,[0,3600,7200]);self.assertEqual(sleeps,[3510,3510,3510])

    def test_long_scans_do_not_overlap_or_run_a_burst_of_missed_checks(self):
        now=[0];starts=[]
        def job():starts.append(now[0]);now[0]+=4000
        def sleep(seconds):
            now[0]+=seconds
            if len(starts)==2:raise StopSchedule
        with patch.object(schedule.time,'monotonic',side_effect=lambda:now[0]),patch.object(schedule.time,'sleep',side_effect=sleep):
            with self.assertRaises(StopSchedule):schedule.hourly(job)
        self.assertEqual(starts,[0,7200])

    def test_same_catalog_lock_prevents_overlap_but_modes_stay_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            device=Path(directory)/'device.json';telegram=Path(directory)/'telegram.json'
            with schedule.scan_lock(device) as first:
                self.assertTrue(first)
                with schedule.scan_lock(device) as duplicate:self.assertFalse(duplicate)
                with schedule.scan_lock(telegram) as other:self.assertTrue(other)
            with schedule.scan_lock(device) as released:self.assertTrue(released)

    def test_unexpected_failure_does_not_stop_hourly_maintenance(self):
        calls=[]
        def job():calls.append(True);raise OSError('lock unavailable')
        with patch.object(schedule.time,'monotonic',return_value=0),patch.object(schedule.time,'sleep',side_effect=[None,StopSchedule]),patch('builtins.print'):
            with self.assertRaises(StopSchedule):schedule.hourly(job)
        self.assertEqual(len(calls),2)

    def test_mac_lease_renewal_is_separate_from_public_catalog_discovery(self):
        vpn=SimpleNamespace(lock=threading.RLock(),nodes={'local':SimpleNamespace(ssh_host='northline-local-node')},catalogs={'telegram':{'own':object()}})
        with patch('settings.MTPROXY_NODE_ID','own'),patch.object(local_maintenance.subprocess,'run') as run:
            local_maintenance.renew(vpn)
        self.assertEqual(len(run.call_args_list),2)
        self.assertTrue(all(call.args[0][-1]=='map' for call in run.call_args_list))

    def test_runtime_preflight_verifies_tun_and_capabilities_before_pruning(self):
        with patch.object(schedule.shutil,'which',return_value='/bin/docker'),patch.object(schedule.subprocess,'run') as run:
            schedule.require_probe('northline-openvpn-probe:local')
        command=run.call_args_list[1].args[0]
        self.assertIn('NET_ADMIN',command);self.assertIn('/dev/net/tun',command);self.assertIn('none',command)
        self.assertIn('nl-smoke',command[-1])

    def test_unusable_runtime_rejects_scan_even_when_the_image_exists(self):
        with patch.object(schedule.shutil,'which',return_value='/bin/docker'),patch.object(schedule.subprocess,'run',side_effect=[None,subprocess.CalledProcessError(1,['docker']),None]):
            with self.assertRaises(RuntimeError):schedule.require_probe('northline-openvpn-probe:local')

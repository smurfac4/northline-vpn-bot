import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock,patch

from deploy import node_control
import run


class RestartAndMetricsTests(unittest.TestCase):
    def test_node_metrics_never_return_peer_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory);(path/'subnet').write_text('10.77.0.0/24')
            with patch.object(node_control,'DIRECTORY',path),patch.object(node_control,'wg',return_value='SECRET-PEER-KEY\t100\t200\nOTHER-KEY\t300\t400\n'),patch('sys.stdout',new_callable=io.StringIO) as output:
                node_control.control(['metrics'])
            result=json.loads(output.getvalue())
            self.assertEqual(result,{'rx_bytes':400,'tx_bytes':600,'peer_count':2})
            self.assertNotIn('KEY',output.getvalue())

    def test_restart_marker_stops_children_before_reexecution(self):
        marker=Mock();marker.exists.return_value=True;marker.read_text.side_effect=['before','after']
        process=Mock();process.poll.return_value=None
        with patch.object(run.settings,'RESTART_FILE',marker),patch('run.signal.signal'),patch('run.subprocess.Popen',return_value=process):
            result=run.main()
        self.assertEqual(result,75)
        self.assertGreaterEqual(process.terminate.call_count,1)
        process.wait.assert_called()

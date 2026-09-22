import os
import sys
import unittest

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import app


class AuthFallbackTests(unittest.TestCase):
    def test_get_account_from_request_uses_query_account_when_no_token(self):
        with app.app.test_request_context('/api/stats?account=DemoUser', method='GET'):
            self.assertEqual(app.get_account_from_request(), 'DemoUser')


if __name__ == '__main__':
    unittest.main()

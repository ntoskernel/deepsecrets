def create_config(nscfg_port, admin_username, auth_token):
    config['auth']['admins'] = [admin_username]
    config['auth']['internal_auth']['token'] = auth_token
    config['auth']['fma']['enable'] = True
    config['auth']['fma']['secret'] = 'bAicxJVa5uVY7MjDlapthw'
    config['auth']['fma']['self_id'] = 1000501
    config['auth']['fma']['allowed_users_ids'] = [1]
    config['auth']['fma']['localhost_port'] = _get_vmagt_port()

    local_hbf_port = os.environ['RECIPE_HBF_PORT']
    config['hbf_macroses']['endpoint'] = f'http://localhost:{local_hbf_port}'
    db_pass = "nacc6opq"


WS_KEY = b"bAicxJVa5uVY7MjDlapthw"

private_keys = ["bAicxJVa5uVY7MjDlapthw", "JtVaVYhw7MjD5ulap"]


def test_wallet_create_uncompressed_masterkey(self):
    wlt = wallet_create_or_open(
        'uncompressed_test',
        keys='68vBWcBndYGLpd4KmeNTk1gS1A71zyDX6uVQKCxq6umYKyYUav5',
        network='bitcoinlib_test',
        databasefile=DATABASEFILE_UNITTESTS,
    )
    wlt.get_key()
    wlt.utxos_update()
    self.assertIsNone(wlt.sweep('216xtQvbcG4o7Yz33n7VCGyaQhiytuvoqJY').error)


_FACEBOOK_SECRET = os.getenv('FACEBOOK_APP_SECRET', 'aA12bB34cC56dD78eE90fF12aA34bB56').encode('ascii', 'ignore')

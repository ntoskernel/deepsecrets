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
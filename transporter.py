import requests
import requests.auth
import time
import os.path


def transfer_post(from_user, to_user, post_id):
    save_post(to_user, post_id)
    unsave_post(from_user, post_id)


def move_saved(from_user, to_user, filterfn=lambda x: x, should_remove=False):
    from_saved_posts = get_saved(from_user)
    to_saved_post_ids = map(lambda x: x['data']['name'], get_saved(to_user))
    for post in from_saved_posts:
        if post['data']['name'] in to_saved_post_ids:
            continue
        if filterfn(post):
            post_id = post['name']
            save_post(to_user, post_id)
            if should_remove:
                unsave_post(from_user, post_id)


def save_post(username, postid):
    response = requests.post('https://oauth.reddit.com/api/save', headers=headers_for_user(username),
                             data={"id": postid})
    if 'error' in response.json():
        raise ValueError('Unable to save post {} for username {}'.format(postid, username), response.json(),
                         response.headers)


def unsave_post(username, postid):
    response = requests.post('https://oauth.reddit.com/api/unsave', headers=headers_for_user(username),
                             data={"id": postid})
    if 'error' in response.json():
        raise ValueError('Unable to unsave post {} for username {} '.format(postid, username), response.json(),
                         response.headers)


def get_all_saved(username, filterfn=lambda x: True):
    saved = []
    after_id = None
    while True:
        response = get_saved(username, after_id)
        after_id = response['data']['after']
        for child in response['data']['children']:
            if filterfn(child):
                saved.append(child)
        if after_id is None:
            break
    saved.reverse()
    return saved


def get_saved(username, after_id=None):
    options = '?limit=100'
    if after_id is not None:
        options += '&after=' + after_id
    request_url = 'https://oauth.reddit.com/user/' + username + '/saved' + options
    response = requests.get(request_url,
                            headers=headers_for_user(username))
    if 'error' in response.json():
        raise ValueError('Error retrieving saved posts for username {}'.format(username), response.json(),
                         response.headers)
    else:
        return response.json()


def initial_auth(username):
    creds = credentials(username)
    request_time = time.time()
    client_auth = requests.auth.HTTPBasicAuth(creds[2], creds[3])
    post_data = {"grant_type": "password", "username": username, "password": creds[1]}
    headers = {"User-Agent": "Transporter by " + username};
    response = requests.post("https://www.reddit.com/api/v1/access_token", auth=client_auth, data=post_data,
                             headers=headers)
    auth_response = response.json()
    if 'error' in auth_response:
        raise ValueError(
            'Unable to auth with Reddit API. Check your credentials file is correct for username {}'.format(username),
            response.json(), response.headers)
    else:
        token = auth_response['access_token']
        expiry = str(int(request_time + auth_response['expires_in']))
        with get_tokens_file() as tokens:
            lines = tokens.readlines()
            tokens.seek(0)
            tokens.truncate()
            new_line = '{}|{}|{}\n'.format(username, token, expiry)
            if len(lines) == 0:
                tokens.write(new_line)
                return
            written = False
            for line in lines:
                if line != '':
                    parts = line.rstrip().split('|')
                    if parts[0] == username:
                        tokens.write(new_line)
                        written = True
                    else:
                        tokens.write(line)
            if not written:
                tokens.write(new_line)


def get_user_token(username):
    with get_tokens_file() as tokens:
        while True:
            line = tokens.readline()
            if line != '' and line[0] == '#':
                continue
            if line != '':
                parts = line.rstrip().split('|')
                if parts[0] == username and time.time() < int(parts[2]):
                    return parts[1]
            else:
                return None


def get_tokens_file():
    if not os.path.isfile('./tokens'):
        with open('tokens', 'w+') as example:
            example.write('# Lines starting with a \'#\' will be ignored.\n')
            example.write('# An example set of tokens follows this format(without the leading #):\n')
            example.write('# username|token|expirytimemilliseconds\n')
    return open('tokens', 'r+')


def credentials(username):
    if not os.path.isfile('./credentials'):
        print "Error: Credentials file missing. Creating the template..."
        with open('credentials', 'w+') as example:
            example.write('# Lines starting with a \'#\' will be ignored.\n')
            example.write('# An example set of credentials follows this format(without the leading #):\n')
            example.write('# username|password|clientid|clientsecret\n')
        raise ValueError('Missing credentials file. Please fill in the created example.')
    with open('credentials', 'r+') as creds_file:
        while True:
            line = creds_file.readline()
            if line != '' and line[0] == '#':
                continue
            if line != '':
                creds = line.rstrip().split('|')
                if creds[0] == username:
                    if len(creds) < 4:
                        raise ValueError(
                            'Incomplete credentials for {}. Only {} values found.'.format(username, len(creds)))
                    else:
                        return creds
            else:
                raise ValueError('No credentials for username {}'.format(username))


def pretty_credentials(username):
    creds = credentials(username)
    print 'Username:\t{}\nPassword:\t{}\nClient ID:\t{}\tClient Secret:\t{}\n'.format(username, creds[1], creds[2],
                                                                                      creds[3])


def headers_for_user(username):
    token = get_user_token(username)
    if token is None:
        initial_auth(username)
        token = get_user_token(username)
    return {"User-Agent": "Transporter by " + username, "Authorization": "bearer " + token}


def simply_posts(posts):
    return map(lambda post: default_post_return_formatter(post), posts)


def default_post_return_formatter(post):
    return post['data'].get('name'), post['data'].get('subreddit'), post['data'].get('permalink'), post['data'].get(
        'kind'), post['data'].get('link_title')


def save_posts_to_file(posts, filename, filemode='w+'):
    with open(filename, filemode) as tempfile:
        map(lambda x: tempfile.write("{} | {} | {}".format(x[0], x[1].encode('utf-8') if x[1] is not None else '',
                                                           x[2].encode('utf-8') if x[2] is not None else '')), posts)


def filter_by_choice(posts, string_for_post_choice):
    chosen = []
    for post in posts:
        choice_str = string_for_post_choice(post)
        choice = make_choice(choice_str)
        if choice is None:
            return chosen
        if choice:
            chosen.append(post)
    return chosen


def make_choice(query):
    previous_choice = None
    while True:
        choice = raw_input(query)
        if choice == '' and previous_choice == '':
            return None
        previous_choice = choice
        if choice == 'Y' or choice == 'y':
            return True
        elif choice == 'N' or choice == 'n':
            return False
        else:
            print choice
            print 'I don\'t understand that response. Try again.'


def pretty_print_posts(posts, *fields):
    for post in posts:
        post_as_str = ''
        for field in fields:
            if field in post['data']:
                post_as_str += "({}: {}) ".format(field, post['data'][field].encode('utf-8'))
            else:
                post_as_str += "({}: undefined key)".format(field)
        print post_as_str

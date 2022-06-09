<?php

/**
 * User Check
 *
 * Roundcube plugin that checks if users belong to a whitelist or blacklist.
 *
 * https://github.com/sbehuret/roundcube-plugin-user-check
 *
 * @version 1.3
 * @author Sébastien Béhuret <sebastien@behuret.net>
 */

class user_check extends rcube_plugin
{
    public function init()
    {
        rcube_plugin::load_config();

        $rcmail = rcube::get_instance();

        $user_check_enabled = $rcmail->config->get('user_check_enabled', false);
        $user_check_during = $rcmail->config->get('user_check_during', 'both');

        if (!is_bool($user_check_enabled)) {
            $rcmail->write_log('errors', 'Setting user_check_enabled must be a boolean');
            return;
        }

        if (!in_array($user_check_during, ['authenticate', 'session', 'both'])) {
            $rcmail->write_log('errors', 'Setting user_check_during must be one of authenticate, session or both');
            return;
        }

        if (!$user_check_enabled)
            return;

        if (in_array($user_check_during, ['authenticate', 'both']))
            $this->add_hook('authenticate', [$this, 'authenticate']);

        if (in_array($user_check_during, ['session', 'both']) && $rcmail->user && $rcmail->user->ID && !$this->filter_pass($rcmail->user->data['username'])) {
            $rcmail->session->log('Aborting session for ' . $rcmail->user->data['username'] . ': Denied by user_check configuration');
            $rcmail->kill_session();
            exit();
        }
    }

    public function get_real_user($user, $master_user_separator)
    {
        $string_length = strlen($user);

        if ($string_length == 0 || $user == $master_user_separator)
            return $user;

        $separator_position = strpos($user, $master_user_separator);

        if ($separator_position === false)
            return $user;

        if ($separator_position === 0)
            return '';

        if ($separator_position === $string_length - 1)
            return substr($user, 0, $string_length - 1);

        return explode($master_user_separator, $user)[0];
    }

    public function split_user_and_domain($login)
    {
        $string_length = strlen($login);

        if ($string_length == 0 || $login == '@')
            return [null, null];

        $at_position = strpos($login, '@');

        if ($at_position === false)
            return [$login, null];

        if ($at_position === 0)
            return [null, substr($login, 1, $string_length - 1)];

        if ($at_position === $string_length - 1)
            return [substr($login, 0, $string_length - 1), null];

        return explode('@', $login, 2);
    }

    public function user_domain_match($splitted_username, $splitted_filter)
    {
        if ($splitted_filter[0] ==! null && $splitted_filter[1] === null && $splitted_username[0] == $splitted_filter[0])
            return true;
        if ($splitted_filter[0] === null && $splitted_filter[1] ==! null && $splitted_username[1] == $splitted_filter[1])
            return true;
        if ($splitted_filter[0] ==! null && $splitted_filter[1] ==! null && $splitted_username[0] == $splitted_filter[0] && $splitted_username[1] == $splitted_filter[1])
            return true;
        else
            return false;
    }

    public function authenticate($args)
    {
        $rcmail = rcube::get_instance();

        $user_check_denied = $rcmail->config->get('user_check_denied', '');
        $user_check_master_user_separator = $rcmail->config->get('user_check_master_user_separator', '*');

        if (!is_string($user_check_denied)) {
            $rcmail->write_log('errors', 'Setting user_check_denied must be a string that can be empty');
            return true;
        }

        if (!is_null($user_check_master_user_separator) && !is_string($user_check_master_user_separator) || (is_string($user_check_master_user_separator) && !strlen($user_check_master_user_separator))) {
            $rcmail->write_log('errors', 'Setting user_check_master_user_password must be null or a non-empty string');
            return true;
        }

        $user = ($user_check_master_user_separator === null ? $args['user'] : self::get_real_user($args['user'], $user_check_master_user_separator));

        if (!$this->filter_pass($user)) {
            $args['abort'] = true;
            $args['error'] = $rcmail->config->get('user_check_denied', '');
        }

        return $args;
    }

    public function filter_pass($username)
    {
        $rcmail = rcube::get_instance();

        $user_check_mode = $rcmail->config->get('user_check_mode', 'blacklist');
        $user_check_filters = $rcmail->config->get('user_check_filters', []);

        if (!in_array($user_check_mode, ['whitelist', 'blacklist'])) {
            $rcmail->write_log('errors', 'Setting user_check_mode must be one of whitelist or blacklist');
            return true;
        }

        if (!is_array($user_check_filters)) {
            $rcmail->write_log('errors', 'Setting user_check_filters must be an array of filters such as user@domain.tld, user(@) or @domain.tld');
            return true;
        }

        $splitted_username = self::split_user_and_domain($username);
        $filter_pass = ($user_check_mode == 'whitelist' ? false : true);

        foreach ($user_check_filters as $user_check_filter) {
            $splitted_filter = self::split_user_and_domain($user_check_filter);

            if (self::user_domain_match($splitted_username, $splitted_filter)) {
                if ($user_check_mode == 'whitelist')
                    $filter_pass = true;
                else
                    $filter_pass = false;

                break;
            }
        }

        return $filter_pass;
    }
}

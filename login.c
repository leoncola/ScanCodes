/*
 * =====================================================================================
 *
 *       Filename:  login.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  07/26/2014 10:39:45 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:   (), 
 *        Company:  
 *
 * =====================================================================================
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/time.h>

#include "debug.h"
#include "utils.h"
#include "vtparse.h"
#include "stream.h"

#include "xsh/channel.h"
#include "xsh/login.h"

#define	AUTOLOGIN_UNKNOW	0
#define	AUTOLOGIN_OK		1


#define	PROMPT_STATE_UNKNOW		0
#define	PROMPT_STATE_PASSWORD		1
#define	PROMPT_STATE_USERNAME		2
#define	PROMPT_STATE_YESNO		3
#define	PROMPT_STATE_ANYKEY		4

#define	LOGIN_STAGE1		(1)
#define	LOGIN_STAGE2		(2)
#define	LOGIN_STAGE3		(3)
#define	LOGIN_STAGE4		(4)
#define	LOGIN_STAGE_DONE	(5)


struct xsh_login {
	struct xsh_channel *channel;

	int confirm;
	int stage;
	int result;
	int PressAnyKey;
	char EnterYesNo[12];
	char *username;
	char *password;
	char *command;
	int echo;
	int password_sent;
	int username_sent;

	long ts_start;
	long ts_idle;
	struct xsh_timeout timeout;

	STREAM *prompt_buffer;
	char *prompt_username;
	char *prompt_password;
	char *prompt_stage2;
	char *prompt_stage3;
	char *prompt_stage4;
};


static void prompt_vtparse_callback(vtparse_t *vt, vtparse_action_t action, unsigned char ch)
{
	char **p = (char **)vt->user_data;

	switch (action) {
		/* we are interesting on only printable characters */
	case VTPARSE_ACTION_PRINT:
		**p = (char)ch;
		*p = *p + 1;
		break;

	default:
		break;
	}

	return;
}

static int login_eol_is_echo(STREAM *s)
{
	unsigned char *c;

	stream_set_nul(s);
	c = stream_get_head(s);
	while (*c) {
		if (*c != 0x00 && *c != '\n' && *c != '\r') {
			return 0;
		}
		c++;
	}

	return 1;
}


static int login_password_is_echo(struct xsh_login *login, STREAM *s)
{
	char *prompt;

	stream_set_nul(s);
	prompt = (char *)stream_get_head(s);

	/* make sure the PASSWORD is not echoed */
	if (strstr(prompt, login->password)) {
		return 1;
	}

	/* it works well.. */
	if (strstr(prompt, "***")) {
		return 1;
	}

	return 0;
}


static char *login_prompt_strip(char *prompt)
{
	vtparse_t vt;
	char *p = prompt;

	vtparse_init(&vt, prompt_vtparse_callback, &p);
	vtparse(&vt, (unsigned char *)prompt, strlen(prompt));
	*p = '\0';

	return prompt;
}


#undef	ARRAY_SIZE
#define	ARRAY_SIZE(a)	((int)(sizeof(a)/sizeof((a)[0])))
static int login_prompt_match(struct xsh_login *login, const char *prompt, 
				  const char **static_candidates, int static_count,
				  const char **dynamic_candidates, int dynamic_count)
{
	int i;
	const char *candidate;

	for (i = 0; i < static_count; i++) {
		candidate = static_candidates[i];
		if (strncasecmp(prompt, candidate, strlen(candidate)) == 0) {
			return 1;
		}
	}

	if (dynamic_candidates) {
		for (i = 0; i < dynamic_count; i++) {
			candidate = dynamic_candidates[i];
			if (strncasecmp(prompt, candidate, strlen(candidate)) == 0) {
				return 1;
			}
		}
	}

	return 0;
}


static int login_prompt_match_username(struct xsh_login *login, const char *prompt)
{
	int dynamic_count = 0;
	const char **dynamic_candidates = NULL;
	static const char *candidates[] = {
		"login",
		"ogin",
		"user",
		"name",
		"username",
		"Enter username",
		"Input username",
		"User name"
	};

	return login_prompt_match(login, prompt, candidates,
				  ARRAY_SIZE(candidates),
				  dynamic_candidates,
				  dynamic_count);
}


static int login_prompt_match_password(struct xsh_login *login, const char *prompt)
{
	int dynamic_count = 0;
	const char **dynamic_candidates = NULL;
	static const char *candidates[] = {
		"Password",
		"assword",
		"Enter password",
		"Input password",
	};

	return login_prompt_match(login, prompt, candidates,
				  ARRAY_SIZE(candidates),
				  dynamic_candidates,
				  dynamic_count);
}


static int login_prompt_match_yesno(struct xsh_login *login, const char *prompt)
{
	/*! @code add check 'yes' or 'no' in line by opencTM/2013-05-22 @endcode */
	memset(login->EnterYesNo, '\0', sizeof(login->EnterYesNo));
	if (NULL != strcasestr(prompt, (char *)"yes/no")) {
		snprintf(login->EnterYesNo, sizeof(login->EnterYesNo), "yes");
	} else if (NULL != strcasestr(prompt, (char *)"y/n")) {
		snprintf(login->EnterYesNo, sizeof(login->EnterYesNo), "y");
	} else {
		return 0;
	}
	return 1;
}

static int login_prompt_match_anykey(struct xsh_login *login, const char *prompt)
{
	char *s = NULL;
	char *p = NULL;
	char *buf = NULL;
	int word = 0;

	/* we only try to guess limit times */
	if (login->PressAnyKey >= 3) {
		return 0;
	}

	/* caculate how many words of the line */
	word = 0;
	buf = strdup(prompt);
	p = buf;
	while ((s = strtok_r(p, " ", &p))) {
		DEBUG2("SSH: prompt word[%d]='%s'\n", word, s);
		word++;
	}
	free(buf);

	/* it is unlikely a prompt of 'USERNAME' or 'PASSWORD' */
	if (word > 3) {
		login->PressAnyKey++;
		return 1;
	}

	return 0;
}


static int login_prompt_state(struct xsh_login *login, char *prompt)
{
	if (login_prompt_match_username(login, prompt)) {
		return PROMPT_STATE_USERNAME;
	} else if (login_prompt_match_password(login, prompt)) {
		return PROMPT_STATE_PASSWORD;
	} else if (login_prompt_match_yesno(login, prompt)) {
		return PROMPT_STATE_YESNO;
	} else if (login_prompt_match_anykey(login, prompt)) {
		return PROMPT_STATE_ANYKEY;
	} else {
		return PROMPT_STATE_UNKNOW;
	}
}


static int login_send_username(struct xsh_login *login, char *prompt)
{
	DEBUG("SSH: send username '%s'\n", login->username);
	xsh_channel_client_printf(login->channel, "%s", login->username);
	/* wait a while for some stupid server such as H3C devices */
	usleep(100 * 1000);
	xsh_channel_client_printf(login->channel, "\r");

	/* save PASSWORD prompt */
	XFREE(login->prompt_username);
	login->prompt_username = strdup(prompt);

	/* disable echo */
	login->echo = 0;
	login->username_sent = 1;
	return 1;
}


static int login_send_password(struct xsh_login *login, char *prompt)
{
	DEBUG("SSH: send password\n");
	xsh_channel_client_printf(login->channel, "%s", login->password);
	/* wait a while for some stupid server such as H3C devices */
	usleep(100 * 1000);
	xsh_channel_client_printf(login->channel, "\r");

	/* save USERNAME prompt */
	XFREE(login->prompt_password);
	login->prompt_password = strdup(prompt);

	/* disable echo */
	login->echo = 0;
	login->password_sent = 1;
	login->stage = (login->confirm) ? (LOGIN_STAGE2) : (LOGIN_STAGE_DONE);
	return 1;
}


static int login_send_yesno(struct xsh_login *login, char *prompt)
{
	/*! @code add send 'yes' or 'y' by opencTM/2013-05-22 @endcode */
	DEBUG("SSH: send (yes/no)? : '%s'\n", login->EnterYesNo);
	xsh_channel_client_printf(login->channel, "%s", login->EnterYesNo);
	xsh_channel_client_printf(login->channel, "\r");
	return 1;
}

static int login_send_anykey(struct xsh_login *login, char *prompt)
{
	DEBUG("SSH: send anykey\n");
	xsh_channel_client_printf(login->channel, "\r");
	return 1;
}

static int login_accept_data(struct xsh_login *login, STREAM *s)
{
	char *buffer;
	size_t length;
	struct xsh_channel *xch = login->channel;

	buffer = (char *)stream_get_head(s);
	length = (size_t)stream_get_length(s);
	xsh_channel_peer_write(xch, buffer, length);
	return 1;
}

static void login_reset_idle(struct xsh_login *login)
{
	login->ts_idle = monotonic_ms();
}

static int login_is_idling(struct xsh_login *login)
{
	long ts;

	switch (login->stage) {
	case LOGIN_STAGE1:
		ts = login->timeout.stage1;
		break;

	default:
		ts = login->timeout.stage2;
		break;
	}

	if ((monotonic_ms() - login->ts_idle) >= ts)
		return 1;
	else
		return 0;
}


static int login_is_timeout(struct xsh_login *login)
{
	if ((monotonic_ms() - login->ts_start) >= login->timeout.login)
		return 1;
	else
		return 0;
}


/* input USERNAME and PASSWORD when in stage1 */
static void xsh_login_stage1(struct xsh_login *login, char *prompt)
{
	DEBUG2("STAGE1 prompt: '%s'\n", prompt);

	prompt = strdup(prompt);
	login_prompt_strip(prompt);

	switch (login_prompt_state(login, prompt)) {
		/* send the password if is being prompted */
	case PROMPT_STATE_PASSWORD:
		if (login->password_sent == 1) {
			ERROR("SSH: meet PASSWORD prompt '%s' again\n", prompt);
			login->stage = LOGIN_STAGE_DONE;
		} else {
			login_send_password(login, prompt);
		}
		break;

		/* send the username if is being prompted */
	case PROMPT_STATE_USERNAME:
		if (login->username_sent == 1) {
			ERROR("SSH: meet USERNAME prompt '%s' again\n", prompt);
			login->stage = LOGIN_STAGE_DONE;
		} else {
			login_send_username(login, prompt);
		}
		break;

		/* "enter yes or no to continue..." */
	case PROMPT_STATE_YESNO:
		login_send_yesno(login, prompt);
		break;

		/* "press any key to continue..." */
	case PROMPT_STATE_ANYKEY:
		login_send_anykey(login, prompt);
		break;

		/* try our best to finish automatialy logon even if we are in 'unknow' prompt */
	case PROMPT_STATE_UNKNOW:
	default:
		ERROR("SSH: unknow prompt '%s'\n", prompt);
		if (login->username_sent == 0 && login->username[0] != '\0') {
			login_send_username(login, prompt);
		} else if (login->password_sent == 0) {
			login_send_password(login, prompt);
		} else {
			ERROR("SSH: have no idea for prompt '%s'\n", prompt);
			login->stage = LOGIN_STAGE_DONE;
		}
		break;
	}
	free(prompt);

	/* don't echo when we are in logon state */
	return;
}


static void xsh_login_stage2(struct xsh_login *login, const char *prompt)
{
	DEBUG2("STAGE2 prompt: '%s'\n", prompt);

	XFREE(login->prompt_stage2);
	login->prompt_stage2 = strdup(prompt);
	login_prompt_strip(login->prompt_stage2);

	/* check if the prompt .. */
	if (strlen(login->prompt_stage2) > 0 &&
	    (strcmp(login->prompt_stage2, login->prompt_username) == 0 ||
	     strcmp(login->prompt_stage2, login->prompt_password) == 0)) {
		login->echo = 1;
		login->stage = LOGIN_STAGE_DONE;
	} else {
		/* step to next stage */
		login->stage = LOGIN_STAGE3;
		xsh_channel_client_printf(login->channel, "\r");
	}

	return;
}


static void xsh_login_stage3(struct xsh_login *login, const char *prompt)
{
	/* in worst case, we will stay in stage3 untill login->timeout.login */
	if (strlen(prompt) > 0) {
		DEBUG2("STAGE3 prompt: '%s'\n", prompt);

		XFREE(login->prompt_stage3);
		login->prompt_stage3 = strdup(prompt);
		login_prompt_strip(login->prompt_stage3);

		/* Logon is failed if the prompt3 match 'USERNAME' or 'PASSWORD' */
		if (strcmp(login->prompt_stage3, login->prompt_username) == 0 ||
		    strcmp(login->prompt_stage3, login->prompt_password) == 0) {
			login->echo = 1;
			login->stage = LOGIN_STAGE_DONE;
		} else {
			/* get a chance to skip 'press any key ....' */
			login->stage = LOGIN_STAGE4;
			xsh_channel_client_printf(login->channel, "\r");
		}
	}

	return;
}


static void xsh_login_stage4(struct xsh_login *login, const char *prompt)
{
	DEBUG2("STAGE4 prompt: '%s'\n", prompt);

	/* in worst case, we will stay in stage3 untill login->timeout.login */
	if (strlen(prompt) > 0) {
		XFREE(login->prompt_stage4);
		login->prompt_stage4 = strdup(prompt);
		login_prompt_strip(login->prompt_stage4);

		login->echo = 1;
		login->stage = LOGIN_STAGE_DONE;
	}

	return;
}

static int xsh_login_finish(struct xsh_login *login)
{
	/* don't check the result */
	if (login->confirm == 0) {
		login->result = LOGIN_RESULT_UNKNOW;
		return LOGIN_DONE;
	}

	DEBUG2("SSH: prompt=|u=%s(%zd)|p=%s(%zd)|s2=%s(%zd)|s3=%s(%zd)|s4=%s(%zd)|\n",
	       login->prompt_username, strlen(login->prompt_username),
	       login->prompt_password, strlen(login->prompt_password),
	       login->prompt_stage2, strlen(login->prompt_stage2),
	       login->prompt_stage3, strlen(login->prompt_stage3),
	       login->prompt_stage4, strlen(login->prompt_stage4));

	/* it is failed if the prompt match 'prompt_username' or 'prompt_password' */
	if (strlen(login->prompt_stage2) > 0 &&
	    (strcmp(login->prompt_stage2, login->prompt_username) == 0 ||
	     strcmp(login->prompt_stage2, login->prompt_password) == 0)) {
		login->result = LOGIN_RESULT_FAILED;

		/* it is failed if the prompt match 'prompt_username' or 'prompt_password' */
	} else if (strcmp(login->prompt_stage3, login->prompt_username) == 0 ||
		   strcmp(login->prompt_stage3, login->prompt_password) == 0) {
		login->result = LOGIN_RESULT_FAILED;

		/* it is failed if the prompt match 'prompt_username' or 'prompt_password' */
	} else if (strcmp(login->prompt_stage4, login->prompt_username) == 0 ||
		   strcmp(login->prompt_stage4, login->prompt_password) == 0) {
		login->result = LOGIN_RESULT_FAILED;

		/* Correct rate depends on timeout.stage2 */
	} else if (strcmp(login->prompt_stage3, login->prompt_stage4) == 0) {
		login->result = LOGIN_RESULT_SUCCESS;

		/* i have no idea what is it, sorry ... */
	}  else {
		login->result = LOGIN_RESULT_UNKNOW;
	}

	return LOGIN_DONE;
}

int xsh_login_check_result(struct xsh_login *login)
{
	return login->result;
}

int xsh_login_receive(struct xsh_login *login,
		      const char *buffer, size_t length)
{
	STREAM *s;
	const unsigned char *p;

	/* timeout */
	if (login_is_timeout(login)) {
		ERROR("SSH: Automatic login timeout (%d ms)\n", login->timeout.login);
		return LOGIN_TIMEOUT;
	}

	s = login->prompt_buffer;
	p = (const unsigned char *)buffer;
	if (length > 0) {
		while (length > 0) {
			stream_write_uint8(s, *p);

			/* DON'T echo PASSWORD or EOL send */
			if (*p == '\n') {
				if (login->stage == LOGIN_STAGE1) {
					if (login->echo) {
						login_accept_data(login, s);
					}
				} else if (!login_password_is_echo(login, s) &&
					   !login_eol_is_echo(s)) {
					login_accept_data(login, s);
				}

				/* FIXME : just for debug only .. */
				//telnet_print_buffer((char *)stream_get_head(s), stream_get_length(s));
				stream_set_pos(s, 0);
			}

			/* step to next byte */
			length--;
			p++;
		}

		/* reset idling timer */
		login_reset_idle(login);
		return LOGIN_INPROGRESS;
	}

	/*!
	 * @code
	 * we __MAY__ caught a prompt if the prompt is not
	 * tailed with '\n' and we are idling.
	 *
	 * empty line is allowed if is not in LOGIN_STAGE1
	 * @endcode
	 */
	if (login_is_idling(login) &&
	    (stream_get_length(s) > 0 || login->stage != LOGIN_STAGE1)) {
		char *prompt;

		/* tailed '\0' */
		stream_set_nul(s);
		prompt = (char *)stream_get_head(s);

		switch (login->stage) {
			/* send USERNAME or PASSWORD */
		case LOGIN_STAGE1:
			xsh_login_stage1(login, prompt);
			break;

			/* check prompt after logon */
		case LOGIN_STAGE2:
			xsh_login_stage2(login, prompt);
			break;

			/* check prompt after logon */
		case LOGIN_STAGE3:
			xsh_login_stage3(login, prompt);
			break;

			/* check prompt after logon */
		case LOGIN_STAGE4:
			xsh_login_stage4(login , prompt);
			break;

		case LOGIN_STAGE_DONE:
		default:
			break;
		}

		/* echo the prompt */
		if (login->echo) {
			login_accept_data(login, s);
		}

		/* reset buffer */
		login_reset_idle(login);
		stream_set_pos(s, 0);

		if (login->stage == LOGIN_STAGE_DONE) {
			return xsh_login_finish(login);
		}
	}

	return LOGIN_INPROGRESS;
}


struct xsh_login *xsh_login_new(struct xsh_channel *channel,
				const char *username,
				const char *password,
				const char *command,
				struct xsh_timeout *timeout,
				int confirm)
{
	struct xsh_login *login;

	login = calloc(1, sizeof(*login));
	if (login) {
		login->channel = channel;
		login->username = (username) ? strdup(username) : strdup("");
		login->password = (password) ? strdup(password) : strdup("");
		login->command  = (command)  ? strdup(command)  : strdup("");
		memset(login->EnterYesNo, '\0', sizeof(login->EnterYesNo));

		login->confirm = confirm;
		login->echo = 1;
		login->PressAnyKey = 0;
		login->stage = LOGIN_STAGE1;

		/* Logon timeout setting */
		login->ts_start = monotonic_ms();
		login->ts_idle  = monotonic_ms();
		login->timeout.login  = 30000;	/* ms: */
		login->timeout.stage1 = 500;	/* stage1: send username and password */
		login->timeout.stage2 = 300;	/* stage2: check if login successfully */
		if (timeout) {
			login->timeout.login  = timeout->login;
			login->timeout.stage1 = timeout->stage1;
			login->timeout.stage2 = timeout->stage2;
		}

		login->prompt_buffer   = stream_new(1024);
		login->prompt_username = strdup("");
		login->prompt_password = strdup("");
		login->prompt_stage2   = strdup("");
		login->prompt_stage3   = strdup("");
		login->prompt_stage4   = strdup("");

		login->result = LOGIN_RESULT_TIMEOUT;
	}

	return login;
}

void xsh_login_free(struct xsh_login *login)
{
	if (login) {
		XFREE(login->username);
		XFREE(login->password);
		XFREE(login->command);

		stream_free(login->prompt_buffer);
		XFREE(login->prompt_username);
		XFREE(login->prompt_password);
		XFREE(login->prompt_stage2);
		XFREE(login->prompt_stage3);
		XFREE(login->prompt_stage4);

		free(login);
	}

	return;
}


/*	$Id$ */
/*
 * Copyright (c) 2016 Kristaps Dzonsons <kristaps@bsd.lv>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <json-c/json.h>

#include "extern.h"

/*
 * The ACME server always serves up JSON.
 * This is used to parse the response as it comes over the wire.
 */
struct	json {
	struct json_tokener	*tok; /* tokeniser */
	struct json_object	*obj; /* result (NULL if pending) */
};

/*
 * Extract an array from the returned JSON object, making sure that it's
 * the correct type.
 * Returns NULL on failure.
 */
static json_object *
json_getarray(json_object *parent, const char *name)
{
	json_object	*p;

	if (json_object_object_get_ex(parent, name, &p) &&
	    json_type_array == json_object_get_type(p))
		return(p);

	return(NULL);
}

/*
 * Extract a single string from the returned JSON object, making sure
 * that it's the correct type.
 * Returns NULL on failure.
 */
static char *
json_getstr(json_object *parent, const char *name)
{
	json_object	*p;
	char		*cp;

	if (json_object_object_get_ex(parent, name, &p) &&
	    json_type_string == json_object_get_type(p) &&
	    NULL != (cp = strdup(json_object_get_string(p))))
		return(cp);

	return(NULL);
}

/*
 * Initialise the JSON object we're going to use multiple time in
 * communicating with the ACME server.
 */
struct json *
json_alloc(void)
{
	struct json	*p;

	if (NULL == (p = calloc(1, sizeof(struct json))))
		return(NULL);

	if (NULL == (p->tok = json_tokener_new())) {
		free(p);
		return(NULL);
	}

	return(p);
}

/*
 * Reset the JSON object between communications with the ACME server.
 * This should be called prior to each invocation, and can be called
 * multiple times around json_free and json_alloc.
 */
void
json_reset(struct json *p)
{

	json_tokener_reset(p->tok);
	if (NULL != p->obj) {
		json_object_put(p->obj);
		p->obj = NULL;
	}
}

/*
 * Completely free the challeng response body.
 */
void
json_free_challenge(struct challenge *p)
{

	free(p->uri);
	free(p->token);
	p->uri = p->token = NULL;
}

/*
 * Completely free the paths response body.
 */
void
json_free(struct json *p)
{

	if (NULL == p)
		return;
	if (NULL != p->tok)
		json_tokener_free(p->tok);
	if (NULL != p->obj)
		json_object_put(p->obj);
	free(p);
}

int
json_parse_response(struct json *json)
{
	char		*resp;
	int		 rc;

	if (NULL == json->obj)
		return(-1);
	if (NULL == (resp = json_getstr(json->obj, "status")))
		return(-1);
	rc = 0 == strcmp(resp, "pending");
	free(resp);
	return(rc);
}

/*
 * Parse the response from a new-authz, which consists of challenge
 * information, into a structure.
 * We only care about the HTTP-01 response.
 */
int
json_parse_challenge(struct json *json, struct challenge *p)
{
	json_object	*array, *obj;
	int		 sz, i, rc;
	char		*type;

	if (NULL == json->obj)
		return(0);

	array = json_getarray(json->obj, "challenges");
	if (NULL == array)
		return(0);
	sz = json_object_array_length(array);
	for (i = 0; i < sz; i++) {
		obj = json_object_array_get_idx(array, i);
		type = json_getstr(obj, "type");
		rc = strcmp(type, "http-01");
		free(type);
		if (rc)
			continue;
		p->uri = json_getstr(obj, "uri");
		p->token = json_getstr(obj, "token");
		return(NULL != p->uri &&
		       NULL != p->token);
	}

	return(0);
}

/*
 * Extract the CA paths from the JSON response object.
 */
int
json_parse_capaths(struct json *json, struct capaths *p)
{

	if (NULL == json->obj)
		return(0);

	p->newauthz = json_getstr(json->obj, "new-authz");
	p->newcert = json_getstr(json->obj, "new-cert");
	p->newreg = json_getstr(json->obj, "new-reg");
	p->revokecert = json_getstr(json->obj, "revoke-cert");

	return(NULL != p->newauthz &&
	       NULL != p->newcert &&
	       NULL != p->newreg &&
	       NULL != p->revokecert);
}

/*
 * Free up all of our CA-noted paths (which may all be NULL).
 */
void
json_free_capaths(struct capaths *p)
{

	free(p->newauthz);
	free(p->newcert);
	free(p->newreg);
	free(p->revokecert);
	memset(p, 0, sizeof(struct capaths));
}

/*
 * Pass an HTTP response body directly to the JSON parser.
 * This will fail once the JSON object has been created (which is the
 * correct operation).
 */
size_t 
jsonbody(void *ptr, size_t sz, size_t nm, void *arg)
{
	struct json	*json = arg;
	enum json_tokener_error er;

	if (NULL != json->obj)
		return(0);

	/* This will be non-NULL when we finish. */
	json->obj = json_tokener_parse_ex(json->tok, ptr, nm * sz);
	er = json_tokener_get_error(json->tok);

	if (er == json_tokener_success || 
	    er == json_tokener_continue)
		return(sz * nm);

	return(0);
}

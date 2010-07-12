/* Copyright (C) 2010 Spiceworks, Inc.  All Rights Reserved. */
#ifndef RUBYNETSNMP_H
#define RUBYNETSNMP_H

#include "ruby.h"
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#ifndef _WIN32
#include <pthread.h>
typedef pthread_mutex_t rubynetsnmp_mutex;
#else
typedef CRITICAL_SECTION rubynetsnmp_mutex;
#endif

// #define _NETSNMP_DEBUG 1 

#define NETSNMP_ERR_SUCCESS					 0
#define NETSNMP_ERR_INVALID_OID              100
#define NETSNMP_ERR_INVALID_TYPE             101
#define NETSNMP_ERR_BADSETVAL                300
#define NETSNMP_ERR_UNKNOWN                  999

#ifdef _WIN32
#define EXPORT_FUNC __declspec(dllexport)
#else
#define EXPORT_FUNC
#endif

#if !defined(_WIN32) && !defined(BOOL)
typedef unsigned char BOOL;
#endif

typedef struct {
	int code;
	char *description;
} NETSNMP_ERROR_TABLE;

NETSNMP_ERROR_TABLE netsnmp_error_table[] = {
	{NETSNMP_ERR_SUCCESS,       "Success"},
	{NETSNMP_ERR_INVALID_OID,   "Object ID is invalid"},
	{NETSNMP_ERR_INVALID_TYPE,  "Invalid type"},
	{NETSNMP_ERR_BADSETVAL,     "Unrecognized or bad value for SET"},
	{NETSNMP_ERR_UNKNOWN,       "Internal error"},
	{0, (char *) NULL}
};

typedef struct _ruby_net_snmp {
	char *host;
	char *community;
	char *userName;
	u_char *contextEngineID;
	char *context;
	u_char *securityEngineID;
	int securityLevel;
    struct snmp_session session, *ss;
    struct snmp_pdu *pdu;
    struct snmp_pdu *response;
    struct variable_list *vars;
    int status;
	char *authPassPhrase;
	char *privPassPhrase;
} ruby_net_snmp;

/* Exposed to Ruby */
EXPORT_FUNC void Init_netsnmp_api();
EXPORT_FUNC VALUE rubynetsnmp_initialize(VALUE self, VALUE hashOptions);
EXPORT_FUNC VALUE rubynetsnmp_get(VALUE self, VALUE vOid);
EXPORT_FUNC VALUE rubynetsnmp_get_bulk(int argc, VALUE *argv, VALUE self);
EXPORT_FUNC VALUE rubynetsnmp_get_value(VALUE self, VALUE vOid);
EXPORT_FUNC VALUE rubynetsnmp_get_next(VALUE self, VALUE vOid);
EXPORT_FUNC VALUE rubynetsnmp_close(VALUE self);
EXPORT_FUNC VALUE rubynetsnmp_get_oid(VALUE self, VALUE vOid);
EXPORT_FUNC VALUE rubynetsnmp_set(int argc, VALUE *argv, VALUE self);
EXPORT_FUNC VALUE rubynetsnmp_error_descr(VALUE self, VALUE errorCode);
EXPORT_FUNC VALUE rubynetsnmp_load_module(VALUE self, VALUE module);
EXPORT_FUNC VALUE rubynetsnmp_get_mib_directory(VALUE self);
EXPORT_FUNC VALUE rubynetsnmp_set_mib_directory(VALUE self, VALUE vMibDir);
EXPORT_FUNC VALUE rubynetsnmp_get_persistent_directory(VALUE self);
EXPORT_FUNC VALUE rubynetsnmp_set_persistent_directory(VALUE self, VALUE vPersistDir);

/* internal prototypes */
void _initialize_netsnmp_lib(void);
int process_oid(VALUE rubyOID, oid *theOID, size_t *theOIDlen);
int process_noids(VALUE ruby_oids, struct snmp_pdu *pdu, VALUE setVals, BOOL isSet);
void raise_exception(VALUE exceptionType, char *format, ...);
void rubynetsnmp_raise_exception(int rc);
void print_oid(const char *label, VALUE oid);
BOOL check_for_multi(VALUE oids);
struct snmp_pdu *internal_netsnmp_get(VALUE netsnmp, VALUE vOid);
VALUE hash_value_for_symbol(VALUE hash, const char *symbol);
VALUE ruby_class_for_name(const char *className, VALUE module);
VALUE ruby_oid(struct variable_list *vars);
VALUE ruby_wrap_variable(struct variable_list *vars, struct snmp_pdu *response);
VALUE ruby_varbind_list(struct snmp_pdu *response);
VALUE ruby_sprintf(char *format, ...);
VALUE new_empty_varbind(void);
void add_set_variable(struct snmp_pdu *pdu, oid *anOID, size_t anOIDLen, VALUE setVals, int pos);
u_char asn_type_for_value(VALUE setVal, int pos);
long rubynetsnmp_long_value(VALUE setVals, int pos);
char *rubynetsnmp_string_value(VALUE setVals, int pos);
float rubynetsnmp_float_value(VALUE setVals, int pos);
VALUE unwrap_varbind(VALUE setVal);
VALUE ruby_class_from(VALUE instance);

#ifdef _NETSNMP_DEBUG
void dump_config(ruby_net_snmp *netsnmp);
#endif

#endif /* RUBYNETSNMP_H */
/* Copyright (C) 2010 Spiceworks, Inc.  All Rights Reserved. */
#include <stdarg.h>
#include <ctype.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include "rubynetsnmp.h"

static VALUE mNetSNMP;
static VALUE cManager;
static VALUE eNetSNMPException;
static VALUE eReqTimeoutException;
rubynetsnmp_mutex mutex;
BOOL netsnmp_initialized = FALSE;
char *mib_directory = NULL;
char *persist_directory = NULL;

/*
# == NetSNMP Manager
#
# The Manager class is used to interact with a single SNMP agent.  It supports all three SNMP versions
# (v1, v2c, v3) and wraps the native Net-SNMP library.   The NetSNMP library tries to be
# compatible with the SNMPlib library.  Configuration hash names can be all lower case (preferred) or
# capitialized (SNMPlib way).  If you are replacing SNMPlib, you can first try out the NetSNMP library
# by inserting a call to NetSNMP.compat(:SNMP) to 'copy' into the SNMP namespace.  This should allow you
# to test before changing any SNMP related calls.
#
# = Examples
#    # SNMP v1
#    require 'net_snmp'
#    manager = NetSNMP::Manager.new(:host => "localhost", :version => :SNMPv1, :community => "public")
#    manager.walk("system").each_varbind {|vb| puts vb.inspect }
#
#    # SNMP v3
#    manager = NetSNMP::Manager.new(:host => "localhost:8161", :version => :SNMPv3, :user => "snmp3user",
#                                   :security_level => :authPriv, :auth_protocol => :MD5, :priv_protocol => :DES)
#    response = manager.set("sysDescr.0", "New system description")
#    if response.error_status == 0
#      puts "Updated system description"
#    else
#      puts response.error_description
#    end

*/
EXPORT_FUNC void rubynetsnmp_mark(void *foo) {
#ifdef _NETSNMP_DEBUG
	printf("netsnmp_mark called\n");
	fflush(stdout);
#endif
}

void _initialize_netsnmp_lib(void) {
	int log_level = LOG_EMERG;
#ifdef _NETSNMP_DEBUG	
	log_level = LOG_DEBUG;
#endif
	netsnmp_log_handler *logh;
	
#ifndef _WIN32
	int rc = pthread_mutex_lock(&mutex);
	if (!rc) {
#else
	EnterCriticalSection(&mutex);
#endif
	if (!netsnmp_initialized) {
		netsnmp_initialized = TRUE;
		
		SOCK_STARTUP;
		logh = netsnmp_register_loghandler(NETSNMP_LOGHANDLER_STDERR, log_level);
	    if (logh) {
	        logh->pri_max = LOG_EMERG;
	        logh->token   = strdup("stdout");
	        logh->imagic  = 1;
		}
		init_snmp("ruby-netsnmp");
	}
#ifndef _WIN32
	pthread_mutex_unlock(&mutex);
#else
	LeaveCriticalSection(&mutex);
#endif

#ifndef _WIN32
	}
	else {
		rb_raise(rb_eRuntimeError, "Unable to acquire lock to initialize netsnmp, return code %d", rc);
	}
#endif
}

EXPORT_FUNC void rubynetsnmp_free(ruby_net_snmp *netsnmp) {
	if (netsnmp->host) { free(netsnmp->host); }
	if (netsnmp->community) { free(netsnmp->community); }
	if (netsnmp->userName) { free(netsnmp->userName); }
	if (netsnmp->authPassPhrase) { free(netsnmp->authPassPhrase); }
	if (netsnmp->privPassPhrase) { free(netsnmp->privPassPhrase); }
	if (netsnmp->securityEngineID) { free(netsnmp->securityEngineID); }
	if (netsnmp->context) { free(netsnmp->context); }
	if (netsnmp->contextEngineID) { free(netsnmp->contextEngineID); }
	if (netsnmp->ss) { snmp_sess_close(netsnmp->ss); }
	free(netsnmp);

#ifdef _NETSNMP_DEBUG
	printf("netsnmp_free called\n");
	fflush(stdout);
#endif
}

EXPORT_FUNC VALUE rubynetsnmp_allocate(VALUE klass) {
	ruby_net_snmp *netsnmp = ALLOC(ruby_net_snmp);
	VALUE result = Qnil;
	
	if (netsnmp) {
		memset(netsnmp, 0, sizeof(ruby_net_snmp));
		result = Data_Wrap_Struct(klass, rubynetsnmp_mark, rubynetsnmp_free, netsnmp);
	}
	return result;
}

/*
 * Cleans up netsnmp session.
 */
EXPORT_FUNC VALUE rubynetsnmp_close(VALUE self) {
	ruby_net_snmp *netsnmp;
	Data_Get_Struct(self, ruby_net_snmp, netsnmp);
	
	if (netsnmp->ss) {
		snmp_sess_close(netsnmp->ss);
		netsnmp->ss = (struct snmp_session *) NULL;
	}
	
	return(self);
}

EXPORT_FUNC void Init_netsnmp_api() {
	mNetSNMP = rb_define_module("NetSNMP");
	cManager = rb_define_class_under(mNetSNMP, "Manager", rb_cObject);
	eNetSNMPException = ruby_class_for_name("SNMPException", mNetSNMP);
	eReqTimeoutException = ruby_class_for_name("RequestTimeout", mNetSNMP);
	rb_define_alloc_func(cManager, rubynetsnmp_allocate);
	rb_define_method(cManager, "initialize", rubynetsnmp_initialize, 1);
	rb_define_method(cManager, "get_value", rubynetsnmp_get_value, 1);
	rb_define_method(cManager, "get_next", rubynetsnmp_get_next, 1);
	rb_define_method(cManager, "get", rubynetsnmp_get, 1);
	rb_define_method(cManager, "get_bulk", rubynetsnmp_get_bulk, -1);
	rb_define_method(cManager, "set", rubynetsnmp_set, -1);
	rb_define_method(cManager, "close", rubynetsnmp_close, 0);
	rb_define_singleton_method(cManager, "create_oid", rubynetsnmp_get_oid, 1);
	rb_define_singleton_method(cManager, "error_description", rubynetsnmp_error_descr, 1);
/*	rb_define_singleton_method(cManager, "load_module", rubynetsnmp_load_module, 1); */
	rb_define_singleton_method(cManager, "mib_directory=", rubynetsnmp_set_mib_directory, 1);
	rb_define_singleton_method(cManager, "mib_directory", rubynetsnmp_get_mib_directory, 0);
	rb_define_singleton_method(cManager, "persistent_directory=", rubynetsnmp_set_persistent_directory, 1);
	rb_define_singleton_method(cManager, "persistent_directory", rubynetsnmp_get_persistent_directory, 0);
	
#ifndef _WIN32
	pthread_mutex_init(&mutex, NULL);
#else
	InitializeCriticalSection(&mutex);
#endif
}

EXPORT_FUNC VALUE rubynetsnmp_set_mib_directory(VALUE self, VALUE vMibDir) {
	if (!NIL_P(vMibDir)) {
		Check_Type(vMibDir, T_STRING);
		netsnmp_set_mib_directory(StringValuePtr(vMibDir));
	}
	return(vMibDir);
}

EXPORT_FUNC VALUE rubynetsnmp_get_mib_directory(VALUE self) {
	char *s = netsnmp_get_mib_directory();
	return(rb_str_new2(s));
}

EXPORT_FUNC VALUE rubynetsnmp_set_persistent_directory(VALUE self, VALUE vPersistDir) {
	if (!NIL_P(vPersistDir)) {
		Check_Type(vPersistDir, T_STRING);
		/* Tell net-snmp where to store mib indexes, etc. */
		set_persistent_directory(StringValuePtr(vPersistDir));
		rb_ivar_set(self, rb_intern("@persistent_directory"), vPersistDir);
	}
	return(vPersistDir);
}

EXPORT_FUNC VALUE rubynetsnmp_get_persistent_directory(VALUE self) {
	return (rb_ivar_get(self, rb_intern("@persistent_directory")));
}

/*
 * Creates a netsnmp session.
 * Just captures the values.  No connection tried here.
 */
EXPORT_FUNC VALUE rubynetsnmp_initialize(VALUE self, VALUE hashOptions) {
	ruby_net_snmp *netsnmp;

	VALUE vHost = hash_value_for_symbol(hashOptions, "host");
	VALUE vSnmp_version = hash_value_for_symbol(hashOptions, "version");
	VALUE vCommunity = hash_value_for_symbol(hashOptions, "community");
	VALUE vRetries = hash_value_for_symbol(hashOptions, "retries");
	VALUE vValue;

	char *host = (char *)"127.0.0.1";
	char *community = (char *)"public";
	int sessionVersion = SNMP_VERSION_2c;  /* Default to 2c */
	ID passedVersion = rb_intern("SNMPv2c");
	int retries = 1;

	/* Used to determine whether we create/open the SNMP session.  Set if errors found during
	   option parsing */
	
	Data_Get_Struct(self, ruby_net_snmp, netsnmp);
	
	if (!NIL_P(vHost)) { host = StringValuePtr(vHost); }
	if (!NIL_P(vCommunity)) { community = StringValuePtr(vCommunity); }
	if (!NIL_P(vSnmp_version)) {
		ID version1 = rb_intern("SNMPv1");
		ID version2 = rb_intern("SNMPv2c");
		ID version3 = rb_intern("SNMPv3");
		
		if (TYPE(vSnmp_version) == T_STRING || TYPE(vSnmp_version) == T_SYMBOL) {
			passedVersion = rb_to_id(vSnmp_version);
		}
		else {
			Check_Type(vSnmp_version, T_SYMBOL);
		}

		if (passedVersion == version1) {
			sessionVersion = SNMP_VERSION_1;
		}
		else if (passedVersion == version2) {
			sessionVersion = SNMP_VERSION_2c;
		}
		else if (passedVersion == version3) {
			sessionVersion = SNMP_VERSION_3;
		}
		else if (passedVersion != version1) {
			raise_exception(eNetSNMPException, "Invalid version [%s]", rb_id2name(passedVersion));
		}
	}
	if (!NIL_P(vRetries)) { 
		Check_Type(vRetries, T_FIXNUM);
		retries = FIX2INT(vRetries);
	}

	/* Sets a instance variables for informative purposes */
	rb_ivar_set(self, rb_intern("@version"), ID2SYM(passedVersion));
	rb_ivar_set(self, rb_intern("@host"), rb_str_new2(host));
	rb_ivar_set(self, rb_intern("@community"), rb_str_new2(community));
	rb_ivar_set(self, rb_intern("@retries"), INT2FIX(retries));
	/* Another compatibility piece for Ruby libsnmp */
	rb_ivar_set(self, rb_intern("@mib"), self);
	
	netsnmp->host = strdup(host);
	netsnmp->community = strdup(community);
	
	/* Called each time, but only initializes net-snmp lib once */
	_initialize_netsnmp_lib();
	
	snmp_sess_init(&netsnmp->session);
	netsnmp->session.peername = netsnmp->host;
	netsnmp->session.retries = retries;
	netsnmp->session.version = sessionVersion;

	vValue = hash_value_for_symbol(hashOptions, "timeout");
	if (!NIL_P(vValue)) {
		if (TYPE(vValue) == T_FLOAT) {
			netsnmp->session.timeout = (long)(NUM2DBL(vValue) * 1000000L);
		}
		else if (TYPE(vValue) == T_FIXNUM) {
			netsnmp->session.timeout = (long)(NUM2INT(vValue) * 1000000L);
		}
		rb_ivar_set(self, rb_intern("@timeout"), vValue);
	}
	else {
		/* 1 second default timeout */
		rb_ivar_set(self, rb_intern("@timeout"), INT2FIX(1));
		netsnmp->session.timeout = 1000000L;
	}
	
	if (sessionVersion < SNMP_VERSION_3) {
		netsnmp->session.community = (u_char *)netsnmp->community;
		netsnmp->session.community_len = strlen(netsnmp->community);
	}
	
	if (sessionVersion == SNMP_VERSION_3) {
		vValue = hash_value_for_symbol(hashOptions, "user");
		if (!NIL_P(vValue)) {
			rb_ivar_set(self, rb_intern("@user"), vValue);
			if (!(netsnmp->session.securityName = netsnmp->userName = strdup(StringValuePtr(vValue)))) {
				rb_raise(rb_eRuntimeError, "Error cloning user name.  Out of memory?");
			}
			netsnmp->session.securityNameLen = strlen(netsnmp->userName);
		}
		vValue = hash_value_for_symbol(hashOptions, "security_level");
		if (!NIL_P(vValue)) {
			if (TYPE(vValue) == T_STRING || TYPE(vValue) == T_SYMBOL) {
				ID authLevel = rb_to_id(vValue);
				if (authLevel == rb_intern("noAuthNoPriv")) {
					netsnmp->session.securityLevel = SNMP_SEC_LEVEL_NOAUTH;
				}
				else if (authLevel == rb_intern("authNoPriv")) {
					netsnmp->session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
				}
				else if (authLevel == rb_intern("authPriv")) {
					netsnmp->session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
				}
				else {
					raise_exception(eNetSNMPException, "Unknown security_level [%s]", rb_id2name(authLevel));
				}
				rb_ivar_set(self, rb_intern("@security_level"), vValue);
			}
			else {
				/* Raise type exception */
				Check_Type(vValue, T_SYMBOL);
			}
		}
		else {
			netsnmp->securityLevel = netsnmp->session.securityLevel = SNMP_SEC_LEVEL_NOAUTH;
		}
		vValue = hash_value_for_symbol(hashOptions, "security_engine_id");
		if (!NIL_P(vValue)) {
			netsnmp->securityEngineID = netsnmp->session.securityEngineID = (u_char *)strdup(StringValuePtr(vValue));
			netsnmp->session.securityEngineIDLen = strlen((char *)netsnmp->securityEngineID);
		}
		vValue = hash_value_for_symbol(hashOptions, "context_engine_id");
		if (!NIL_P(vValue)) {
			netsnmp->contextEngineID = netsnmp->session.contextEngineID = (u_char *)strdup(StringValuePtr(vValue));
			netsnmp->session.contextEngineIDLen = strlen((char *)netsnmp->contextEngineID);
		}
		vValue = hash_value_for_symbol(hashOptions, "auth_pass_phrase");
		if (!NIL_P(vValue)) {
			netsnmp->authPassPhrase = strdup(StringValuePtr(vValue));
		}
		vValue = hash_value_for_symbol(hashOptions, "priv_pass_phrase");
		if (!NIL_P(vValue)) {
			netsnmp->privPassPhrase = strdup(StringValuePtr(vValue));
		}
		vValue = hash_value_for_symbol(hashOptions, "auth_protocol");
		if (!NIL_P(vValue)) {
			ID md5 = rb_intern("MD5");
			ID sha = rb_intern("SHA");
			ID passedValue = Qnil;
			
			if (TYPE(vValue) == T_SYMBOL) {
				passedValue = SYM2ID(vValue);
				if (md5 == passedValue) {
					netsnmp->session.securityAuthProto = usmHMACMD5AuthProtocol;
					netsnmp->session.securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
					netsnmp->session.securityAuthKeyLen = USM_AUTH_KU_LEN;
				}
				else if (sha == passedValue) {
					netsnmp->session.securityAuthProto = usmHMACSHA1AuthProtocol;
					netsnmp->session.securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
					netsnmp->session.securityAuthKeyLen = USM_AUTH_KU_LEN;
				}
				else {
					raise_exception(eNetSNMPException, "Unknown auth_protocol [%s]", rb_id2name(passedValue));
					passedValue = Qnil;
				}
			}
			else {
				/* Force exception */
				Check_Type(vValue, T_SYMBOL);
			}
		}
		vValue = hash_value_for_symbol(hashOptions, "priv_protocol");
		if (!NIL_P(vValue)) {
			if (!NIL_P(vValue)) {
				ID des = rb_intern("DES");
				ID aes = rb_intern("AES");
				ID passedValue = Qnil;

				if (TYPE(vValue) == T_SYMBOL) {
					passedValue = SYM2ID(vValue);
					if (des == passedValue) {
						netsnmp->session.securityPrivProto = usmDESPrivProtocol;
						netsnmp->session.securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
						netsnmp->session.securityPrivKeyLen = USM_AUTH_KU_LEN;
					}
					else if (aes == passedValue) {
						netsnmp->session.securityPrivProto = usmAESPrivProtocol;
						netsnmp->session.securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;
						netsnmp->session.securityPrivKeyLen = USM_PRIV_KU_LEN;
					}
					else {
						raise_exception(eNetSNMPException, "Unknown priv_protocol [%s]", rb_id2name(passedValue));
						passedValue = Qnil;
					}
				}
				else {
					/* Force exception */
					Check_Type(vValue, T_SYMBOL);
				}
			}
		}
		vValue = hash_value_for_symbol(hashOptions, "context");
		if (!NIL_P(vValue)) {
			netsnmp->context = strdup(StringValuePtr(vValue));
		}

		vValue = hash_value_for_symbol(hashOptions, "engine_boots");
		if (!NIL_P(vValue)) {
			Check_Type(vValue, T_FIXNUM);
			netsnmp->session.engineBoots = FIX2INT(vValue);
		}
		vValue = hash_value_for_symbol(hashOptions, "engine_time");
		if (!NIL_P(vValue)) {
			Check_Type(vValue, T_FIXNUM);
			netsnmp->session.engineTime = FIX2INT(vValue);
		}
		
		if (netsnmp->session.securityAuthProto) {
			if (netsnmp->authPassPhrase) {
				int rc = 0;
				if ((rc = generate_Ku(netsnmp->session.securityAuthProto,
			                    netsnmp->session.securityAuthProtoLen,
			                    (u_char *) netsnmp->authPassPhrase, strlen(netsnmp->authPassPhrase),
			                    netsnmp->session.securityAuthKey,
			                    &(netsnmp->session.securityAuthKeyLen))) != SNMPERR_SUCCESS) 
				{
					rb_raise(eNetSNMPException, "Error generating Ku from authentication pass phrase.");
				}
			}
		}
		if (netsnmp->session.securityPrivProto) {
			if (netsnmp->privPassPhrase) {
				if (generate_Ku(netsnmp->session.securityAuthProto, //netsnmp->session.securityPrivProto,
			                    netsnmp->session.securityAuthProtoLen,//netsnmp->session.securityPrivProtoLen,
			                    (u_char *) netsnmp->privPassPhrase, strlen(netsnmp->privPassPhrase),
			                    netsnmp->session.securityPrivKey,
			                    &netsnmp->session.securityPrivKeyLen) != SNMPERR_SUCCESS) 
				{
					rb_raise(eNetSNMPException, "Error generating Ku from privacy pass phrase.");
				}
			}
		}
	} /* end if SNMPv3 check */

#ifdef _NETSNMP_DEBUG
	dump_config(netsnmp);
#endif

	netsnmp->ss = snmp_sess_open(&netsnmp->session);
	if (!netsnmp->ss) {
		rb_raise(eNetSNMPException, "Error creating SNMP session.");
	}
	return self;
}

/*
 * SNMP get of an OID or an array of OIDs
 */
EXPORT_FUNC VALUE rubynetsnmp_get(VALUE self, VALUE vOid) {
	struct snmp_pdu *response;
	VALUE vResult = rb_obj_alloc(ruby_class_for_name("PDU", mNetSNMP));
	VALUE vVarbind = Qnil;
	VALUE vArgv[3];
	
	response = internal_netsnmp_get(self, vOid);
	if (response) {
		vVarbind = ruby_varbind_list(response);
		vArgv[0] = INT2FIX(response->reqid);
		vArgv[1] = vVarbind;
		vArgv[2] = INT2FIX(response->errstat);
		snmp_free_pdu(response);
	}
	else {
		vArgv[0] = INT2FIX(0);
		vArgv[1] = new_empty_varbind();
		vArgv[2] = INT2FIX(SNMP_ERR_GENERR);
	}
	rb_obj_call_init(vResult, 3, vArgv);
	
	return(vResult);
}

/*
# Performs an SNMP get but only returns the value(s)
*/
EXPORT_FUNC VALUE rubynetsnmp_get_value(VALUE self, VALUE vOid) {
	struct snmp_pdu *response;
	VALUE vResult = Qnil;
	VALUE vVarbind;
	VALUE *v;
	int i;
	
	response = internal_netsnmp_get(self, vOid);
	if (response) {
		vVarbind = ruby_varbind_list(response);
		v = RARRAY_PTR(RARRAY(vVarbind));

#if _NETSNMP_DEBUG > 127
		printf("varbind length=%ld\n", RARRAY_LEN(vVarbind));
		fflush(stdout);
#endif
		if (check_for_multi(vOid)) {
			vResult = rb_ary_new();
			for (i = 0; i < RARRAY_LEN(vVarbind); i++) {
				rb_ary_push(vResult, rb_funcall(v[i], rb_intern("value"), 0, 0));
			}
		}
		else {
			vResult = rb_funcall(v[0], rb_intern("value"), 0, 0);
		}
		snmp_free_pdu(response);
	}
	
	return (vResult);
}

/*
# SNMP get_next.  Takes an OID or an array of OIDs.
*/
EXPORT_FUNC VALUE rubynetsnmp_get_next(VALUE self, VALUE vOid) {
	ruby_net_snmp *netsnmp;

	struct snmp_pdu *pdu;
	struct snmp_pdu *response;
	int status;
	int rc = NETSNMP_ERR_SUCCESS;
	char *err;
	VALUE vResult = Qnil;
	VALUE vVarbind = Qnil;
	VALUE vArgv[3];
	VALUE errString;
	
	Data_Get_Struct(self, ruby_net_snmp, netsnmp);
	pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);

	if (!(rc = process_noids(vOid, pdu, Qnil, FALSE))) {
#ifdef HAVE_TBR
    status = (int) gil_release_and_call(3, snmp_sess_synch_response, RUBY_UBF_IO, netsnmp->ss, pdu, &response);
#else
		status = snmp_sess_synch_response(netsnmp->ss, pdu, &response);
#endif
#if _NETSNMP_DEBUG > 1
		printf("netsnmp_get_next: snmp_sync_response rc=%d\n", status);
		fflush(stdout);
#endif
		if (status == STAT_SUCCESS && response) {
			vVarbind = ruby_varbind_list(response);
		}
		else {
			if (STAT_TIMEOUT == status) {
				raise_exception(eReqTimeoutException, "Host %s is not responding.", netsnmp->host);
				return Qnil;
			}
			else {
				snmp_sess_error(netsnmp->ss, NULL, NULL, &err);
				errString = rb_str_new2(err);
				SNMP_FREE(err);
				rb_raise(eNetSNMPException, StringValuePtr(errString));
				return Qnil;
			}
		}
		vResult = rb_obj_alloc(ruby_class_for_name("PDU", mNetSNMP));
		vArgv[0] = INT2FIX(response->reqid);
		vArgv[1] = vVarbind;
		vArgv[2] = INT2FIX(status);
		rb_obj_call_init(vResult, 3, vArgv);
		
		snmp_free_pdu(response);
	}
	else {
		rubynetsnmp_raise_exception(rc);
	}

	return vResult;
}

EXPORT_FUNC VALUE rubynetsnmp_get_oid(VALUE self, VALUE vOid) {
	int rc;
	oid anOID[MAX_OID_LEN];
	size_t anOIDLen = MAX_OID_LEN;
	VALUE vValue = Qnil;
	int i;
	
	if (!(rc = process_oid(vOid, anOID, &anOIDLen))) {
		vValue = rb_obj_alloc(ruby_class_for_name("OID", mNetSNMP));
		for (i = 0; i < anOIDLen; i++) {
			rb_ary_push(vValue, INT2FIX((int)anOID[i]));
		}
	}
	else {
		rubynetsnmp_raise_exception(rc);
	}
	
	return vValue;
}

EXPORT_FUNC VALUE rubynetsnmp_get_bulk(int argc, VALUE *argv, VALUE self) {
	ruby_net_snmp *netsnmp;

	struct snmp_pdu *pdu, 
	                *response = NULL;
	VALUE vVarbind = Qnil;
	VALUE vResult = rb_obj_alloc(ruby_class_for_name("PDU", mNetSNMP));
	VALUE vArgv[3];
	VALUE vOid;
	VALUE vOptions = Qnil;
	VALUE v;
	int rc;
	int non_repeaters = 0;
	int max_repetitions = 10;
	
	Data_Get_Struct(self, ruby_net_snmp, netsnmp);
	
  if (argc < 1) {
    rb_raise(rb_eArgError, "Invalid number of arguments");
    return Qnil;
  }
	
  if (netsnmp->session.version == SNMP_VERSION_1) {
    rb_raise(eNetSNMPException, "get_bulk is only valid for SNMP version v2c and above.");
    return Qnil;
  }
	
	if (argc == 2) {
		vOptions = argv[1];
		Check_Type(vOptions, T_HASH);
	}
	vOid = argv[0];
	if (vOptions != Qnil) {
		v = hash_value_for_symbol(vOptions, "non_repeaters");
		if (v && v != Qnil) {
			non_repeaters = FIX2INT(v);
		}
		v = hash_value_for_symbol(vOptions, "max_repetitions");
		if (v && v != Qnil) {
			max_repetitions = FIX2INT(v);
		}
	}
	pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
	pdu->non_repeaters = non_repeaters;
	pdu->max_repetitions = max_repetitions;
	if (!(rc = process_noids(vOid, pdu, Qnil, FALSE))) {
#ifdef HAVE_TBR
    rc = (int) gil_release_and_call(3, snmp_sess_synch_response, RUBY_UBF_IO, netsnmp->ss, pdu, &response);
#else
		rc = snmp_sess_synch_response(netsnmp->ss, pdu, &response);
#endif
		if (rc == STAT_SUCCESS) {
			if (response) {
				vVarbind = ruby_varbind_list(response);
				vArgv[0] = INT2FIX(response->reqid);
				vArgv[1] = vVarbind;
				vArgv[2] = INT2FIX(response->errstat);
				snmp_free_pdu(response);
			}
			else {
				vArgv[0] = INT2FIX(0);
				vArgv[1] = new_empty_varbind();
				vArgv[2] = INT2FIX(SNMP_ERR_GENERR);
			}
			rb_obj_call_init(vResult, 3, vArgv);
		}
		else if (STAT_TIMEOUT == rc) {
			raise_exception(eReqTimeoutException, "Host %s is not responding.", netsnmp->host);
		}
		else {
			/* ERROR */
			rubynetsnmp_raise_exception(rc);
		}
	}
	else {
		rubynetsnmp_raise_exception(rc);
	}
	
	return vResult;
}

/******* SETS *******/

/*
 * vOid - Array of or single OID
 * val - Array of or single ASN1-typed object
 *
 */
EXPORT_FUNC VALUE rubynetsnmp_set(int argc, VALUE *argv, VALUE self) {
	ruby_net_snmp *netsnmp;

	struct snmp_pdu *pdu, 
	                *response = NULL;
    
	VALUE vResult = rb_obj_alloc(ruby_class_for_name("PDU", mNetSNMP));
	VALUE vVarbind = Qnil;
	VALUE vArgv[3];
	VALUE val = Qnil;
	VALUE vOid;
	int rc;
	
	Data_Get_Struct(self, ruby_net_snmp, netsnmp);
	
#ifdef _NETSNMP_DEBUG
	printf("rubynetsnmp_set: argc=%d\n", argc);
	fflush(stdout);
#endif

	if (argc < 1 || argc > 2) {
		rb_raise(rb_eArgError, "Invalid number of arguments");
		return Qnil;
	}

	/* Expect varbind object if only one argument */
	if (argc == 1) {
		if (TYPE(argv[0]) == T_ARRAY) {
			vOid = argv[0];
		}
		else if (TYPE(argv[0]) == T_OBJECT) {
			if (Qtrue == rb_funcall(argv[0], rb_intern("respond_to?"), 1, ID2SYM(rb_intern("to_varbind")))) {
				vOid = argv[0];
			}
			else {
				rb_raise(rb_eArgError, "Invalid argument");
				return Qnil;
			}
		}
		else {
			rb_raise(rb_eArgError, "Invalid number of arguments");
			return Qnil;
		}
	}
	else {
		vOid = argv[0];
		val = argv[1];
	}
	
	pdu = snmp_pdu_create(SNMP_MSG_SET);
	if (!(rc = process_noids(vOid, pdu, val, TRUE))) {
#ifdef HAVE_TBR
    rc = (int) gil_release_and_call(3, snmp_sess_synch_response, RUBY_UBF_IO, netsnmp->ss, pdu, &response);
#else
		rc = snmp_sess_synch_response(netsnmp->ss, pdu, &response);
#endif
		if (rc == STAT_SUCCESS) {
			if (response) {
				vVarbind = ruby_varbind_list(response);
				vArgv[0] = INT2FIX(response->reqid);
				vArgv[1] = vVarbind;
				vArgv[2] = INT2FIX(response->errstat);
				snmp_free_pdu(response);
			}
			else {
				vArgv[0] = INT2FIX(0);
				vArgv[1] = new_empty_varbind();
				vArgv[2] = INT2FIX(SNMP_ERR_GENERR);
			}
			rb_obj_call_init(vResult, 3, vArgv);
		}
		else {
			/* ERROR */
			rubynetsnmp_raise_exception(rc);
		}
	}
	else {
		rubynetsnmp_raise_exception(rc);
	}
	
	return(vResult);
}

EXPORT_FUNC VALUE rubynetsnmp_error_descr(VALUE self, VALUE errorCode) {
	const char *msg = snmp_errstring(FIX2INT(errorCode));
	return rb_str_new(msg, strlen(msg));
}

/* Doesn't work */
/*
EXPORT_FUNC VALUE rubynetsnmp_load_module(VALUE self, VALUE module) {
	int rc, len, i;
	VALUE *v;
	
	if (TYPE(module) == T_STRING) {
		if (!netsnmp_read_module(StringValuePtr(module))) {
			rb_raise(eNetSNMPException, "Unable to load module %s", StringValuePtr(module));
		}
	}
	else if (TYPE(module) == T_ARRAY) {
		v = RARRAY_PTR(RARRAY(module));
		len = RARRAY_LEN(RARRAY(module));
		for (i = 0; i < len; i++) {
			rubynetsnmp_load_module(self, v[i]);
		}
	}
	
	return Qnil;
}
*/

/*
 * Utility for extracting values from a hash that uses symbol keys
 */
VALUE hash_value_for_symbol(VALUE hash, const char *symbol) {
	char upperSymbol[40];
	char c;
	VALUE vVal = rb_funcall(hash, rb_intern("[]"), 1, ID2SYM(rb_intern(symbol)));
	/* 
	 * For backwards compat with ruby libsnmp.  Capitalize first letter and try again.
	 */
	if (vVal == Qnil) {
		if (symbol[0] != (c = toupper(symbol[0]))) {
			strlcpy(upperSymbol, symbol, sizeof(upperSymbol));
			upperSymbol[0] = c;
			vVal = rb_funcall(hash, rb_intern("[]"), 1, ID2SYM(rb_intern(upperSymbol)));
		}
	}
	return vVal;
}

VALUE ruby_class_from(VALUE instance) {
	return rb_funcall(instance, rb_intern("class"), 0, 0);
}

VALUE ruby_class_for_name(const char *className, VALUE module) {
	ID class_id = rb_intern(className);
	VALUE parent = (module? module : rb_cObject);
	return rb_const_get(parent, class_id);
}

VALUE ruby_oid(struct variable_list *vars) {
	VALUE vOid = Qnil;
	int i;
	
	vOid = rb_obj_alloc(ruby_class_for_name("OID", mNetSNMP));
	for (i = 0; i < vars->name_length; i++) {
		rb_ary_push(vOid, INT2FIX((int)vars->name[i]));
	}
	
	return vOid;
}

VALUE ruby_varbind_list(struct snmp_pdu *response) {
	VALUE vResult;
	VALUE vVar;
	VALUE vArgv[2];
	struct variable_list *vars;
#if _NETSNMP_DEBUG > 127
	int i;
#endif
	
	vars = response->variables;
	vResult = rb_obj_alloc(ruby_class_for_name("VarBindList", mNetSNMP));
	if (vResult) {
		rb_obj_call_init(vResult, 0, 0);
		while (vars) {
			vVar = rb_obj_alloc(ruby_class_for_name("VarBind", mNetSNMP));
			if (vVar) {
#if _NETSNMP_DEBUG > 127
				printf("ruby_varbind_list: adding var ");
				for (i = 0; i < vars->name_length; i++) {
					if (i > 0) printf(".");
					printf("%d", (int)vars->name[i]);
				}
				printf("\n");
				fflush(stdout);
#endif
				vArgv[0] = ruby_oid(vars);
				vArgv[1] = ruby_wrap_variable(vars, response);
				rb_obj_call_init(vVar, 2, vArgv);
				rb_ary_push(vResult, vVar);
			}
			vars = vars->next_variable;
		}
	}
	return vResult;
}

VALUE ruby_wrap_variable(struct variable_list *vars, struct snmp_pdu *response) {
	VALUE vArgv[1];
	VALUE vObj = Qnil;
	int i, oidLen;
	u_char ip[4];
	
	switch (vars->type) {
		case ASN_INTEGER:
#if _NETSNMP_DEBUG > 127
        printf("ruby_wrap_variable: integer: value=%ld\n", *(u_long *)vars->val.integer);
#endif
			vObj = rb_obj_alloc(ruby_class_for_name("Integer", mNetSNMP));
			vArgv[0] = INT2FIX(*((u_long *)vars->val.integer));
			rb_obj_call_init(vObj, 1, vArgv);
			break;
		case ASN_UINTEGER:
#if _NETSNMP_DEBUG > 127
        printf("ruby_wrap_variable: Uinteger: value=%ld\n", *(u_long *)vars->val.integer);
#endif
			vObj = rb_obj_alloc(ruby_class_for_name("UnsignedInteger", mNetSNMP));
			vArgv[0] = INT2FIX(*((u_long *)vars->val.integer));
			rb_obj_call_init(vObj, 1, vArgv);
			break;
		case ASN_OPAQUE:
		case ASN_OCTET_STR:
			vObj = rb_obj_alloc(ruby_class_for_name("OctetString", mNetSNMP));
			if (vObj) {
#if _NETSNMP_DEBUG > 127
        printf("ruby_wrap_variable: OctetStr: value=%s\n", (char *)vars->val.string);
#endif
    		vArgv[0] = rb_str_new((char *)vars->val.string, vars->val_len);
				rb_obj_call_init(vObj, 1, vArgv);
			}
			break;
		case ASN_OBJECT_ID:
			oidLen = vars->val_len / sizeof(oid);
			vObj = rb_obj_alloc(ruby_class_for_name("OID", mNetSNMP));
			if (vObj) {
				rb_obj_call_init(vObj, 0, 0);
				i = 0;
				while (i < oidLen) {
					rb_ary_push(vObj, INT2FIX(vars->val.objid[i++]));
				}
			}
			break;
		case ASN_TIMETICKS:
#if _NETSNMP_DEBUG > 127
      printf("ruby_wrap_variable: timeticks: value=%ld\n", *(u_long *)vars->val.integer);
#endif
			vObj = rb_obj_alloc(ruby_class_for_name("TimeTicks", mNetSNMP));
			if (vObj) {
				vArgv[0] = INT2FIX(*((u_long *)vars->val.integer));
				rb_obj_call_init(vObj, 1, vArgv);
			}
			break;
		case ASN_IPADDRESS:
#if _NETSNMP_DEBUG > 127
    printf("ruby_wrap_variable: ipaddress %d.%d.%d.%d\n", 
    	(u_char)((((unsigned int) *(vars->val.integer)) & 0xff000000) >> 24),
			(u_char)((((unsigned int) *(vars->val.integer)) & 0x00ff0000) >> 16),
			(u_char)((((unsigned int) *(vars->val.integer)) & 0x0000ff00) >> 8),
			(u_char)(((unsigned int) *(vars->val.integer)) & 0x000000ff)
	  );
#endif
			vObj = rb_obj_alloc(ruby_class_for_name("IpAddress", mNetSNMP));
			if (vObj) {
				ip[3] = (u_char)((((unsigned int) *(vars->val.integer)) & 0xff000000) >> 24);
				ip[2] = (u_char)((((unsigned int) *(vars->val.integer)) & 0x00ff0000) >> 16);
				ip[1] = (u_char)((((unsigned int) *(vars->val.integer)) & 0x0000ff00) >> 8);
				ip[0] = (u_char)(((unsigned int) *(vars->val.integer)) & 0x000000ff);
				vArgv[0] = rb_str_new((char *)ip, 4);
				rb_obj_call_init(vObj, 1, vArgv);
			}
			break;
		case ASN_OPAQUE_FLOAT:
			vObj = rb_obj_alloc(ruby_class_for_name("Float", mNetSNMP));
			if (vObj) {
				vArgv[0] = rb_float_new(*((float *)vars->buf));
				rb_obj_call_init(vObj, 1, vArgv);
			}
			break;
		case ASN_OPAQUE_DOUBLE:
			vObj = rb_obj_alloc(ruby_class_for_name("Double", mNetSNMP));
			if (vObj) {
				vArgv[0] = rb_float_new(*((double *)vars->buf));
				rb_obj_call_init(vObj, 1, vArgv);
			}
			break;
		case ASN_COUNTER:
			vObj = rb_obj_alloc(ruby_class_for_name("Counter32", mNetSNMP));
			vArgv[0] = INT2FIX(*((u_long *)vars->val.integer));
			rb_obj_call_init(vObj, 1, vArgv);
			break;
		case ASN_GAUGE:
			vObj = rb_obj_alloc(ruby_class_for_name("Gauge", mNetSNMP));
			vArgv[0] = INT2FIX(*((u_long *)vars->val.integer));
			rb_obj_call_init(vObj, 1, vArgv);
			break;
		case ASN_COUNTER64:
			vObj = rb_obj_alloc(ruby_class_for_name("Counter64", mNetSNMP));
			if (vObj) {
				vArgv[0] = INT2FIX(*((u_long *)vars->val.integer));
				rb_obj_call_init(vObj, 1, vArgv);
			}
			break;

		case SNMP_NOSUCHOBJECT:
			vObj = ruby_class_for_name("NoSuchObject", mNetSNMP);
			break;
        case SNMP_NOSUCHINSTANCE:
			vObj = ruby_class_for_name("NoSuchInstance", mNetSNMP);
			break;
        case SNMP_ENDOFMIBVIEW:
			vObj = ruby_class_for_name("EndOfMibView", mNetSNMP);
			break;
        case ASN_NULL:
			if (response->errstat != SNMP_ERR_NOERROR) {
				vObj = ruby_class_for_name("Null", mNetSNMP);
			}
			break;
	        
		default:
			vObj = ruby_sprintf("*** Unimplemented variable type 0x%02x ***", vars->type);
			break;
	}
	
	return (vObj);
}

/* Scans passed in OID and checks for non-integer array */
BOOL check_for_multi(VALUE ruby_oids) {
	BOOL rc = FALSE;
	VALUE *v;
	
	if (TYPE(ruby_oids) == T_ARRAY) {
		v = RARRAY_PTR(RARRAY(ruby_oids));
		if (RARRAY_LEN(ruby_oids) > 0) {
			if (TYPE(v[0]) != T_FIXNUM) {
				rc = TRUE;
			}
		}
	}
	return(rc);
}

/* Processes N number of OIDs.  Ruby can pass a string, an OID, a varbind, or
 * an array of strings/OIDs/varbinds.  setVals is NULL for gets.
 */
int process_noids(VALUE ruby_oids, struct snmp_pdu *pdu, VALUE setVals, BOOL isSet) {
	BOOL multiOids = FALSE;
	VALUE *v;
	oid anOID[MAX_OID_LEN];
	size_t anOIDLen = MAX_OID_LEN;
	int rc = NETSNMP_ERR_SUCCESS;
	int i;
	VALUE vals;
	
	multiOids = check_for_multi(ruby_oids);
	
#if _NETSNMP_DEBUG > 127
	printf("\nprocess_noids: %s\n\n", (multiOids? "Multiple OIDs detected" : "Single OID detected"));
	fflush(stdout);
#endif

	if (multiOids) {
		v = RARRAY_PTR(RARRAY(ruby_oids));
		for (i = 0; i < RARRAY_LEN(ruby_oids); i++) {
			anOIDLen = MAX_OID_LEN;
			if (!(rc = process_oid(v[i], anOID, &anOIDLen))) {
				if (isSet) {
					vals = (setVals && setVals != Qnil? setVals : ruby_oids);
					add_set_variable(pdu, anOID, anOIDLen, vals, i);
				}
				else {
					snmp_add_null_var(pdu, anOID, anOIDLen);
				}
			}
#ifdef _NETSNMP_DEBUG 
			else {
				print_oid("(Multi) Bad OID", v[i]);
				break;
			}
#endif
		}
	}
	else {
		if (!(rc = process_oid(ruby_oids, anOID, &anOIDLen))) {
			if (isSet) {
				vals = (setVals && setVals != Qnil? setVals : ruby_oids);
				add_set_variable(pdu, anOID, anOIDLen, vals, 0);
			}
			else {
				snmp_add_null_var(pdu, anOID, anOIDLen);
			}
		}
#ifdef _NETSNMP_DEBUG 
		else {
			print_oid("(Single) Bad OID", ruby_oids);
		}
#endif
		
	}
	
	return (rc);
}

/*
 * setVals - Ruby value(s)
 * pos - variable position
 * 
 */
void add_set_variable(struct snmp_pdu *pdu, oid *anOID, size_t anOIDLen, VALUE setVals, int pos) {
	u_char cType;
	/* Used to temporarily hold values for the add_variable calls */
	long l;
	float f;
	char *cp;
	in_addr_t addr;

	cType = asn_type_for_value(setVals, pos);
	switch (cType) {
		case ASN_INTEGER:
		case ASN_GAUGE:
		case ASN_UINTEGER:
		case ASN_TIMETICKS:
			l = rubynetsnmp_long_value(setVals, pos);
			snmp_pdu_add_variable(pdu, anOID, anOIDLen, cType, (u_char *)&l, sizeof(l));
			break;

		case ASN_OCTET_STR:
			cp = rubynetsnmp_string_value(setVals, pos);
			snmp_pdu_add_variable(pdu, anOID, anOIDLen, cType, (u_char *)cp, strlen(cp));
			break;
			
		case ASN_IPADDRESS:
			addr = inet_addr(rubynetsnmp_string_value(setVals, pos));
			snmp_pdu_add_variable(pdu, anOID, anOIDLen, cType, (u_char *)&addr, sizeof(addr));
			break;
			
		case ASN_OPAQUE_FLOAT:
			f = rubynetsnmp_float_value(setVals, pos);
			snmp_pdu_add_variable(pdu, anOID, anOIDLen, cType, (u_char *)&f, sizeof(f));
			break;
			
		default:
			rubynetsnmp_raise_exception(NETSNMP_ERR_UNKNOWN);
			break;
	}
	
	return;
}

long rubynetsnmp_long_value(VALUE setVals, int pos) {
	long l = 0L;
	VALUE *v;
	VALUE val = unwrap_varbind(setVals);
	
	if (TYPE(val) == T_ARRAY) {
		v = RARRAY_PTR(RARRAY(val));
		l = rubynetsnmp_long_value(v[pos], 0);
	}
	else if (TYPE(val) == T_FIXNUM) {
		l = (long) FIX2INT(val);
	}
	return l;
}

char *rubynetsnmp_string_value(VALUE setVals, int pos) {
	char *s = NULL;
	VALUE *v;
	VALUE val = unwrap_varbind(setVals);
	
	if (TYPE(val) == T_ARRAY) {
		v = RARRAY_PTR(RARRAY(val));
		s = rubynetsnmp_string_value(v[pos], 0);
	}
	else if (TYPE(val) == T_STRING) {
		s = StringValuePtr(val);
	}
	
	return s;
}

float rubynetsnmp_float_value(VALUE setVals, int pos) {
	float f = 0.0;
	VALUE *v;
	VALUE val = unwrap_varbind(setVals);
	
	if (TYPE(val) == T_ARRAY) {
		v = RARRAY_PTR(RARRAY(val));
		f = rubynetsnmp_float_value(v[pos], 0);
	}
	else if (TYPE(val) == T_STRING) {
		f = (float) NUM2DBL(val);
	}

	return f;
}

VALUE unwrap_varbind(VALUE setVal) {
	VALUE result = setVal;
	
	if (TYPE(setVal) == T_OBJECT) {
		if (Qtrue == rb_funcall(setVal, rb_intern("respond_to?"), 1, ID2SYM(rb_intern("to_varbind")))) {
			result = rb_funcall(setVal, rb_intern("value"), 0, 0);
		}
	}
	
	return result;
}

/*
 * Gets the internal ASN type for the given Ruby object.  The Ruby object
 * can be a Ruby primitive, Ruby SNMP variable, Ruby VarBind, or an array.
 */
u_char asn_type_for_value(VALUE setVal, int pos) {
	int asnType = 0;
	VALUE gpv;
	VALUE *v;
	
	switch (TYPE(setVal)) {
		case T_ARRAY:
			/* This could be a regular array or an OID */
			if (Qtrue == rb_funcall(setVal, rb_intern("respond_to?"), 1, ID2SYM(rb_intern("subtree_of?")))) {
				asnType = ASN_OBJECT_ID;
			}
			else {
				v = RARRAY_PTR(RARRAY(setVal));
				asnType = asn_type_for_value(v[pos], 0);
			}
			break;
		
		case T_FIXNUM:
			asnType = ASN_INTEGER;
			break;
		
		case T_STRING:
			asnType = ASN_OCTET_STR;
			break;
		
		case T_FLOAT:
			asnType = ASN_OPAQUE_FLOAT;
			break;
		
		case T_OBJECT:
			/* varbind object? */
			if (Qtrue == rb_funcall(setVal, rb_intern("respond_to?"), 1, ID2SYM(rb_intern("to_varbind")))) {
#ifdef _NETSNMP_DEBUG
				printf("asn_type_for_value: Found varbind object.  Extracting value.\n");
				fflush(stdout);
#endif
				gpv = rb_funcall(setVal, rb_intern("value"), 0, 0);
				asnType = asn_type_for_value(gpv, 0);
			}
			else if (Qtrue == rb_funcall(setVal, rb_intern("respond_to?"), 1, ID2SYM(rb_intern("asn1_type")))) {
				asnType = (u_char) FIX2INT(rb_const_get(ruby_class_from(setVal), rb_intern("ASN_TYPE")));
			}
			else {
				rubynetsnmp_raise_exception(NETSNMP_ERR_BADSETVAL);
			}
			break;
		default:
			rubynetsnmp_raise_exception(NETSNMP_ERR_BADSETVAL);
			break;
	}
	
	return(asnType);
}

/*
 * Utility function for dealing with Ruby OID values.  Options are
 * an array of FixInt or a String.  This processes and populates the
 * OID array for netsnmp.
 */
int process_oid(VALUE ruby_oid, oid *theOID, size_t *theOIDlen) {
	int i, rc = 0;
	VALUE *v;
	VALUE vValue;
	
	switch (TYPE(ruby_oid)) {
		case T_STRING:
			if (!snmp_parse_oid(StringValuePtr(ruby_oid), theOID, theOIDlen)) { 
				rc = NETSNMP_ERR_INVALID_OID; 
			}
			break;
		
		case T_ARRAY:
			v = RARRAY_PTR(RARRAY(ruby_oid));
			for (i = 0; i < RARRAY_LEN(ruby_oid); i++) {
				if (TYPE(v[i]) == T_FIXNUM) {
					if (i < *theOIDlen) {
						theOID[i] = (oid) FIX2INT(v[i]);
					}
					else {
						rc = NETSNMP_ERR_INVALID_OID;
						break;
					}
				}
				else {
					rc = NETSNMP_ERR_INVALID_OID;
					break;
				}
			}
			if (rc == 0) { *theOIDlen = i; }
			break;
		
		default:
			/* varbind object? */
			if (Qtrue == rb_funcall(ruby_oid, rb_intern("respond_to?"), 1, ID2SYM(rb_intern("to_varbind")))) {
				vValue = rb_funcall(ruby_oid, rb_intern("to_varbind"), 0, 0);
				if (vValue) {
					vValue = rb_funcall(vValue, rb_intern("name"), 0, 0);
					if (vValue) {
						/* Should have string or OID array now */
						rc = process_oid(vValue, theOID, theOIDlen);
					}
				}
			}
			else {
				rc = NETSNMP_ERR_INVALID_TYPE;
			}
			break;
	}
	
	return (rc);
}

VALUE new_empty_varbind(void) {
	VALUE vVarbind = Qnil;
	
	vVarbind = rb_obj_alloc(ruby_class_for_name("VarBindList", mNetSNMP));
	rb_obj_call_init(vVarbind, 0, 0);
	
	return (vVarbind);
}

VALUE ruby_sprintf(char *format, ...) {
	va_list ap;
	char msg[1024] = "\0";

	va_start(ap, format);
	vsnprintf(msg, sizeof(msg), format, ap);
	va_end(ap);
	return (rb_str_new(msg, strlen(msg)));
}

void raise_exception(VALUE exceptionType, const char *format, ...) {
	va_list ap;
	char msg[1024] = "\0";
	VALUE v;
	va_start(ap, format);
	vsnprintf(msg, sizeof(msg), format, ap);
	va_end(ap);
	v = rb_str_new(msg, strlen(msg));
	rb_raise(exceptionType, StringValuePtr(v));
}

#ifdef _NETSNMP_DEBUG
void dump_config(ruby_net_snmp *netsnmp) {
	char *secLevel = "noAuthNoPriv";
	char *authProto = "UNK";
	char *privProto = "UNK";

	printf("\nRuby NetSNMP Configuration\n==========================\n");
	printf("Host: %s\n", netsnmp->host);
	printf("Port: %d\n", netsnmp->session.remote_port);
	printf("SNMP Version: %ld\n", netsnmp->session.version);
	if (netsnmp->session.version == SNMP_VERSION_3) {
		if (netsnmp->userName) { printf("\tUser: %s\n", netsnmp->userName); }
		if (netsnmp->authPassPhrase) { printf("\tAuth Pass Phrase: [%s]\n", netsnmp->authPassPhrase); }
		if (netsnmp->privPassPhrase) { printf("\tPriv Pass Phrase: [%s]\n", netsnmp->privPassPhrase); }
		if (netsnmp->session.securityLevel == SNMP_SEC_LEVEL_AUTHNOPRIV) {
			secLevel = "authNoPriv";
		}
		else if (netsnmp->session.securityLevel == SNMP_SEC_LEVEL_AUTHPRIV) {
			secLevel = "authPriv";
		}
		printf("\tv3 Security Level: %s\n", secLevel);
		if (!strncmp(secLevel, "auth", 4)) {
			if (!memcmp(netsnmp->session.securityAuthProto, usmHMACMD5AuthProtocol, sizeof(usmHMACMD5AuthProtocol))) {
				authProto = "MD5";
			}
			else if (!memcmp(netsnmp->session.securityAuthProto, usmHMACSHA1AuthProtocol, sizeof(usmHMACSHA1AuthProtocol))) {
				authProto = "SHA";
			}
			printf("\tAuth Protocol %s\n", authProto);
		}
		if (!strncmp(secLevel, "authPriv", 8)) {
			if (!memcmp(netsnmp->session.securityPrivProto, usmDESPrivProtocol, sizeof(usmDESPrivProtocol))) {
				privProto = "DES";
			}
			else if (!memcmp(netsnmp->session.securityPrivProto, usmAESPrivProtocol, sizeof(usmAESPrivProtocol))) {
				privProto = "AES";
			}
			printf("\tPriv Protocol %s\n", privProto);
		}
		if (netsnmp->session.securityEngineID) {
			printf("Security Engine ID: %s\n", netsnmp->session.securityEngineID);
		}
		if (netsnmp->session.contextEngineID) {
			printf("Context Engine ID: %s\n", netsnmp->session.contextEngineID);
		}
	}
	else if (netsnmp->community) { 
		printf("Community: %s\n", netsnmp->community);
	}
	printf("Retries: %d\n", netsnmp->session.retries);
	
	printf("\n");
}
#endif

/*
 * Internal get.  DOES NOT FREE THE RESPONSE!  Caller
 * must call snmp_free_pdu(response) when done processing it.
 */
struct snmp_pdu *internal_netsnmp_get(VALUE self, VALUE vOid) {
	ruby_net_snmp *netsnmp;
	struct snmp_pdu *pdu;
	struct snmp_pdu *response;
	int status;
	VALUE errString;
	char *err;
	
	Data_Get_Struct(self, ruby_net_snmp, netsnmp);
	pdu = snmp_pdu_create(SNMP_MSG_GET);
	if (!(status = process_noids(vOid, pdu, Qnil, FALSE))) {
	  
#ifdef HAVE_TBR
    status = (int) gil_release_and_call(3, snmp_sess_synch_response, RUBY_UBF_IO, netsnmp->ss, pdu, &response);
#else
		status = snmp_sess_synch_response(netsnmp->ss, pdu, &response);
#endif
	
		if (status != STAT_SUCCESS) {
			if (STAT_TIMEOUT == status) {
				raise_exception(eReqTimeoutException, "Host %s is not responding.", netsnmp->host);
			}
			else {
				snmp_sess_error(netsnmp->ss, NULL, NULL, &err);
				errString = rb_str_new2(err);
				SNMP_FREE(err);
				rb_raise(eNetSNMPException, StringValuePtr(errString));
			}
		}
	}
	else {
		rubynetsnmp_raise_exception(status);
	}
	
	return (response);
}

/* Raises an exception using an NETSNMP return code */
void rubynetsnmp_raise_exception(int rc) {
	int i;
	char *err_txt = "internal error";
	
	for(i = 0; netsnmp_error_table[i].description; i++) {
		if (netsnmp_error_table[i].code == rc) {
			err_txt = netsnmp_error_table[i].description;
			break;
		}
		else if (netsnmp_error_table[i].code > rc) {
			break;
		}
	}
	rb_raise(eNetSNMPException, err_txt);
}

void print_oid(const char *label, VALUE vOid) {
	int i;
	VALUE *v;
	
	printf("%s: ", label);
	
	switch (TYPE(vOid)) {
		case T_STRING:
			printf("%s\n", StringValuePtr(vOid));
			break;
		case T_ARRAY:
			v = RARRAY_PTR(vOid);
			for (i = 0; i < RARRAY_LEN(vOid); i++) {
				if (i > 0) {
					printf(".");
				}
				if (TYPE(v[i] == T_FIXNUM)) {
					printf("%ld", FIX2INT(v[i]));
				}
				else if (TYPE(v[i] == T_STRING)) {
					printf("%s", StringValuePtr(v[i]));
				}
				else {
					printf("?");
				}
			}
			printf("\n");
			break;
		default:
			printf("Unknown OID format.\n");
			break;
			
	}
	fflush(stdout);
}

#ifdef HAVE_TBR
/* 
  argc - Number of parameters provided to pass to function
  void *func_ptr - Function pointer of function to invoke
  void *interrupt_func_ptr - Function pointer of interrupt function
  void *func_arg x argc
*/
void *gil_release_and_call(int argc, ...) {
  va_list vargs;
  int i;
  FUNCTION_WRAPPER func_wrapper;
  void *interrupt_func_ptr;
  
  va_start(vargs, argc);
  func_wrapper.func_ptr = va_arg(vargs, void *);
  interrupt_func_ptr = va_arg(vargs, void *);
  func_wrapper.argc = argc;
  
  for (i = 0; i < argc && i < MAX_WRAP_ARGUMENTS; i++) {
    void *arg = va_arg(vargs, void *);
    func_wrapper.args[i] = arg;
  }
  va_end(vargs);

  return((void *)rb_thread_blocking_region((rb_blocking_function_t *)invoke_function, (void *)&func_wrapper, interrupt_func_ptr, 0));
}

static void *invoke_function(void *fwrapper) {
  FUNCTION_WRAPPER *func_wrapper = fwrapper;
  void *result = (void *)NULL;
  
#if _NETSNMP_DEBUG > 127
  printf("invoke_function reached.\n");
  printf("\tNumber of arguments: %d\n", func_wrapper->argc);
#endif
  switch (func_wrapper->argc) {
    case 0:
      {
        void *(*func_ptr)(void) = func_wrapper->func_ptr;
        result = func_ptr();
      }
      break;
    case 1:
      {
        void *(*func_ptr)(void *) = func_wrapper->func_ptr;
        result = func_ptr(func_wrapper->args[0]);
      }
      break;
    case 2:
      {
        void *(*func_ptr)(void *, void *) = func_wrapper->func_ptr;
        result = func_ptr(func_wrapper->args[0], func_wrapper->args[1]);
      }
      break;
    case 3:
      {
        void *(*func_ptr)(void *, void *, void *) = func_wrapper->func_ptr;
        result = func_ptr(func_wrapper->args[0], func_wrapper->args[1], func_wrapper->args[2]);
      }
      break;
    case 4:
      {
        void *(*func_ptr)(void *, void *, void *, void *) = func_wrapper->func_ptr;
        result = func_ptr(func_wrapper->args[0], func_wrapper->args[1], func_wrapper->args[2], func_wrapper->args[3]);
      }
      break;
    case 5:
      {
        void *(*func_ptr)(void *, void *, void *, void *, void *) = func_wrapper->func_ptr;
        result = func_ptr(func_wrapper->args[0], func_wrapper->args[1], func_wrapper->args[2], 
                          func_wrapper->args[3], func_wrapper->args[4]);
      }
      break;
    case 6:
      {
        void *(*func_ptr)(void *, void *, void *, void *, void *, void *) = func_wrapper->func_ptr;
        result = func_ptr(func_wrapper->args[0], func_wrapper->args[1], func_wrapper->args[2],
                          func_wrapper->args[3], func_wrapper->args[4], func_wrapper->args[5]);
      }
      break;
    case 7:
      {
        void *(*func_ptr)(void *, void *, void *, void *, void *, void *, void *) = func_wrapper->func_ptr;
        result = func_ptr(func_wrapper->args[0], func_wrapper->args[1], func_wrapper->args[2],
                          func_wrapper->args[3], func_wrapper->args[4], func_wrapper->args[5],
                          func_wrapper->args[6]);
      }
      break;
    case 8:
      {
        void *(*func_ptr)(void *, void *, void *, void *, void *, void *, void *, void *) = func_wrapper->func_ptr;
        result = func_ptr(func_wrapper->args[0], func_wrapper->args[1], func_wrapper->args[2], 
                          func_wrapper->args[3], func_wrapper->args[4], func_wrapper->args[5],
                          func_wrapper->args[6], func_wrapper->args[7]);
      }
      break;
    default:
      fprintf(stderr, "Unsupported number of arguments.\n");
      break;
  }
  
  return(result);
}
#endif

#ifdef _WIN32
BOOL APIENTRY DllMain(HANDLE hModule, 
                      DWORD  ul_reason_for_call, 
                      LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    	break;
    case DLL_THREAD_ATTACH:
    	break;
    case DLL_THREAD_DETACH:
    	break;
    case DLL_PROCESS_DETACH:
    	break;
    }
    return TRUE;
}
#endif

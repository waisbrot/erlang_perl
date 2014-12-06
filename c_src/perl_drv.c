/* author Kevin Smith <ksmith@basho.com>
    perl_destruct(my_perl);
    perl_free(my_perl);
   copyright 2009-2010 Basho Technologies

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License. */

#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <erl_driver.h>

#include "config.h"
#include "driver_comm.h"
#include "erl_compatibility.h"
#include <EXTERN.h>
#include <perl.h>
#define CV_NAMESPACE "ErlDriver::_subs"
extern char **environ;

EXTERN_C void xs_init (pTHX);
static PerlInterpreter *my_perl = NULL;
static SV *json_object = NULL;

typedef struct _perl_drv_t {
  ErlDrvPort port;
  ErlDrvTermData atom_ok;
  ErlDrvTermData atom_error;
  ErlDrvTermData atom_unknown_cmd;
} perl_drv_t;

typedef struct _perl_call_t {
  perl_drv_t *driver_data;
  ErlDrvBinary *args;
  ErlDrvTermData return_terms[20];
  char return_call_id[32];
  int return_term_count;
  const char *return_string;
} perl_call;

typedef void (*asyncfun)(void *);


/* Forward declarations */
static ErlDrvData start(ErlDrvPort port, char *cmd);
static int init(void);
static void stop(ErlDrvData handle);
static void finish(void);

static void process(ErlDrvData handle, ErlIOVec *ev);
static void ready_async(ErlDrvData handle, ErlDrvThreadData async_data);

static ErlDrvEntry perl_drv_entry = {
    init,                             /* init */
    start,                            /* startup */
    stop,                             /* shutdown */
    NULL,                             /* output */
    NULL,                             /* ready_input */
    NULL,                             /* ready_output */
    (char *) "erlang_perl_drv",         /* the name of the driver */
    finish,                             /* finish */
    NULL,                             /* handle */
    NULL,                             /* control */
    NULL,                             /* timeout */
    process,                          /* process */
    ready_async,                      /* ready_async */
    NULL,                             /* flush */
    NULL,                             /* call */
    NULL,                             /* event */
    ERL_DRV_EXTENDED_MARKER,          /* ERL_DRV_EXTENDED_MARKER */
    ERL_DRV_EXTENDED_MAJOR_VERSION,   /* ERL_DRV_EXTENDED_MAJOR_VERSION */
    ERL_DRV_EXTENDED_MINOR_VERSION,   /* ERL_DRV_EXTENDED_MINOR_VERSION */
    ERL_DRV_FLAG_USE_PORT_LOCKING     /* ERL_DRV_FLAGs */
};


void send_immediate_ok_response(perl_drv_t *dd, const char *call_id) {
  ErlDrvTermData terms[] = {ERL_DRV_BUF2BINARY, (ErlDrvTermData) call_id, strlen(call_id),
                            ERL_DRV_ATOM, dd->atom_ok,
                            ERL_DRV_TUPLE, 2};
  erl_drv_output_term(driver_mk_port(dd->port), terms, sizeof(terms) / sizeof(terms[0]));
}

#define COPY_DATA(CD, CID, TERMS)                                         \
    do {                                                                  \
         assert(strlen(CID) < sizeof(CD->return_call_id) - 1); \
         strcpy(CD->return_call_id, CID);                      \
         assert(sizeof(TERMS) <= sizeof(CD->return_terms));        \
         memcpy(CD->return_terms, TERMS, sizeof(TERMS));           \
         CD->return_term_count = sizeof(TERMS) / sizeof(TERMS[0]); \
    } while (0)

void send_ok_response(perl_drv_t *dd, perl_call *call_data,
                      const char *call_id) {
  ErlDrvTermData terms[] = {ERL_DRV_BUF2BINARY,
                            (ErlDrvTermData) call_data->return_call_id,strlen(call_id),
                            ERL_DRV_ATOM, dd->atom_ok,
                            ERL_DRV_TUPLE, 2};
  COPY_DATA(call_data, call_id, terms);
}

void send_error_string_response(perl_drv_t *dd, perl_call *call_data,
                                const char *call_id, const char *msg) {
  ErlDrvTermData terms[] = {ERL_DRV_BUF2BINARY,
                            (ErlDrvTermData) call_data->return_call_id,strlen(call_id),
                            ERL_DRV_ATOM, dd->atom_error,
                            ERL_DRV_BUF2BINARY, (ErlDrvTermData) msg, strlen(msg),
                            ERL_DRV_TUPLE, 3};
  COPY_DATA(call_data, call_id, terms);
  call_data->return_string = msg;
}

void send_string_response(perl_drv_t *dd, perl_call *call_data,
                          const char *call_id, const char *result) {
  ErlDrvTermData terms[] = {ERL_DRV_BUF2BINARY,
                            (ErlDrvTermData) call_data->return_call_id,strlen(call_id),
                            ERL_DRV_ATOM, dd->atom_ok,
                            ERL_DRV_BUF2BINARY, (ErlDrvTermData) result, strlen(result),
                            ERL_DRV_TUPLE, 3};
  COPY_DATA(call_data, call_id, terms);
  call_data->return_string = result;
}

void unknown_command(perl_drv_t *dd, perl_call *call_data,
                     const char *call_id) {
  ErlDrvTermData terms[] = {ERL_DRV_BUF2BINARY,
                            (ErlDrvTermData) call_data->return_call_id,strlen(call_id),
                            ERL_DRV_ATOM, dd->atom_error,
                            ERL_DRV_ATOM, dd->atom_unknown_cmd,
                            ERL_DRV_TUPLE, 3};
  COPY_DATA(call_data, call_id, terms);
}

int sv_to_json(SV* input, char **dst) {
    AV *wrapper = av_make(1, &input);

    STRLEN len;
    int retval;

    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    XPUSHs(json_object);
    XPUSHs(newRV((SV*)wrapper));
    PUTBACK;
    int count = call_method("encode", G_EVAL);
    SPAGAIN;
    if (SvTRUE(ERRSV))
    {
        STRLEN len;
        char *errmsg = SvPV(ERRSV, len);
        *dst = eperl_alloc(len+1);
        memcpy(*dst, errmsg, len+1);
        retval = 0;
    } else {
        SV *encoded_result = POPs;
        char *json_ptr = SvPV(encoded_result, len);
        *dst = eperl_alloc(len+1);
        memcpy(*dst, json_ptr, len+1);
        retval = 1;
    }

    PUTBACK;
    FREETMPS;
    LEAVE;
    return retval;
}



void _build_interpreter() {
    char *embedding[] = { "", "-MJSON::XS", "-e", "0" };
    my_perl = perl_alloc();
    perl_construct(my_perl);
    perl_parse(my_perl, xs_init, 4, embedding, environ);
    perl_run(my_perl);

    json_object = eval_pv("JSON::XS->new->allow_nonref", TRUE);
}
void _destroy_interpreter() {
    perl_destruct(my_perl);
    perl_free(my_perl);
    my_perl = NULL;
}

int perl_eval(const char *code, char **result) {
  SV* ret_sv = eval_pv(code, FALSE);
  if (SvTRUE(ERRSV))
  {
    STRLEN len;
    char *errmsg = SvPV(ERRSV, len);
    *result = eperl_alloc(len+1);
    memcpy(*result, errmsg, len+1);
    return 0;
  } else if (result != NULL) {
    sv_to_json(ret_sv, result);
  }
  return 1;
}

char *perl_run_cv(const char *sub, SV *args) {
    char *retval = NULL;

    if (sub == NULL) {
        return NULL;
    }

    char * full_name = eperl_alloc(sizeof(CV_NAMESPACE) + 2 + strlen(sub));
    sprintf(full_name, "%s::%s", CV_NAMESPACE, sub);
    CV *cv = get_cv(full_name, 0);
    if (cv == NULL) {
        warn("No such CV: '%s'\n", full_name);
        goto end_run_cv;
    }

    dSP;

    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    if (args) {
        XPUSHs(args);
        PUTBACK;
    }

    int number = call_sv((SV*) cv, G_SCALAR|G_KEEPERR);

    SPAGAIN;

    if (number == 1) {
        SV *result = POPs;
        sv_to_json(result, &retval);
    } else {
        warn("Wrong number of values returned: '%i'\n", number);
    }

    PUTBACK;
    FREETMPS;
    LEAVE;

    end_run_cv:
    driver_free(full_name);

    return retval;
}


int perl_compile_cv(const char *code, char **result) {
    SV *svcv = eval_pv(code, FALSE);
    if (SvTRUE(ERRSV))
    {
        STRLEN len;
        char *errmsg = SvPV(ERRSV, len);
        *result = eperl_alloc( len + 1);
        memcpy( *result, errmsg, len + 1);
        return 0;
    } else {

        /* Dereference */
        if (SvROK(svcv)) {
            svcv = SvRV(svcv);
        }

        if (SvTYPE(svcv) == SVt_PVCV) {
            SvREFCNT_inc(svcv);

            GV *gv = (GV*)SvREFCNT_inc(newGVgen(CV_NAMESPACE));
            if ( GvCV(gv) )
                die("cv '%s' already exists", SvPV_nolen((SV*)gv));

            GvCV_set(gv, (CV*)svcv);
            STRLEN len;
            char *name = SvPV((SV*)gv, len);
            name += sizeof(CV_NAMESPACE) + 2;
            len -= sizeof(CV_NAMESPACE) + 2;
            *result = eperl_alloc( len + 1);
            memcpy( (void*)*result, name, len + 1);
        } else {
            STRLEN len;
            char *obj = SvPV(svcv, len);
            *result = eperl_alloc( sizeof("code \"%s\" returned something that is not a code reference: \"%s\"") + strlen(code) + len);
            sprintf(*result,"code \"%s\" returned something that is not a code reference: \"%s\"", code, obj);
            return 0;
        }
    }
    return 1;
}

void run_js(void *jsargs) {
  perl_call *call_data = (perl_call *) jsargs;
  perl_drv_t *dd = call_data->driver_data;
  ErlDrvBinary *args = call_data->args;
  char *data = args->orig_bytes;
  char *command = read_command(&data);
  char *call_id = read_string(&data);
  char *result = NULL;

  if (strncmp(command, "rp", 2) == 0) {
    _destroy_interpreter();
    _build_interpreter();
    send_ok_response(dd, call_data, call_id);
  }
  else if (strncmp(command, "ip", 2) == 0) {
    char *code = read_string(&data);
    int ok = perl_compile_cv(code, &result);
    if (ok) {
        send_string_response(dd, call_data, call_id, result);
    } else {
        send_error_string_response(dd, call_data, call_id, result);
    }
    driver_free(code);
  }
  else if (strncmp(command, "cp", 2) == 0) {
    char *sub = read_string(&data);
    char *args_json = read_string(&data);
    SV *args = NULL;
    if (args_json[0] != 0) {
        dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(json_object);
        XPUSHs(newSVpv(args_json, 0));
        PUTBACK;
        int count = call_method("decode", G_SCALAR);
        SPAGAIN;
        args = newSVsv(POPs);
        PUTBACK;
        FREETMPS;
        LEAVE;
    }

    result = perl_run_cv(sub, args);

    if (result == NULL) {
        result =  eperl_alloc(1);
        result[0] = 0;
    }

    send_string_response(dd, call_data, call_id, result);
    driver_free(sub);
    driver_free(args_json);
  }
  else if (strncmp(command, "ep", 2) == 0) {
    char *code = read_string(&data);
    if (perl_eval(code, &result)) {
      send_string_response(dd, call_data, call_id, result);
    }
    else {
      send_error_string_response(dd, call_data, call_id, result);
    }
    driver_free(code);
  }
  else if (strncmp(command, "dj", 2) == 0) {
    char *filename = read_string(&data);
    char *code = read_string(&data);
    if (perl_eval(code, &result)) {
      send_string_response(dd, call_data, call_id, result);
    }
    else {
      send_error_string_response(dd, call_data, call_id, result);
    }
    driver_free(filename);
    driver_free(code);
  }
  else {
    unknown_command(dd, call_data, call_id);
  }
  driver_free(command);
  driver_free(call_id);
}

DRIVER_INIT(perl_drv) {
  return &perl_drv_entry;
}

static int init(void) {
  static int sa = 0;
  if (!sa++) {
    char *argv[] = { };
    int argc = 0;
    PERL_SYS_INIT3(&argc, (char ***)&argv, &environ);
    _build_interpreter();
  }
  return 0;
}

static ErlDrvData start(ErlDrvPort port, char *cmd) {
  perl_drv_t *retval = eperl_alloc(sizeof(perl_drv_t));
  retval->port = port;
  retval->atom_ok = driver_mk_atom((char *) "ok");
  retval->atom_error = driver_mk_atom((char *) "error");
  retval->atom_unknown_cmd = driver_mk_atom((char *) "unknown_command");

  /* Lock the driver in memory.  NSPR registers some thread cleanup
  ** code in _pt_thread_death on the async thread pool which
  ** gets called after spidermonkey_drv.so is unloaded on R15B
  */
  driver_lock_driver(port);

  return (ErlDrvData) retval;
}

static void finish(void) {
     _destroy_interpreter();
     PERL_SYS_TERM();
}

static void stop(ErlDrvData handle) {
  perl_drv_t *dd = (perl_drv_t*) handle;
  driver_free(dd);
}

static void process(ErlDrvData handle, ErlIOVec *ev) {
  perl_drv_t *dd = (perl_drv_t *) handle;
  char *data = ev->binv[1]->orig_bytes;
  char *command = read_command(&data);

  perl_call *call_data = eperl_alloc(sizeof(perl_call));
  call_data->driver_data = dd;
  call_data->args = ev->binv[1];
  call_data->return_terms[0] = 0;
  call_data->return_term_count = 0;
  call_data->return_string = NULL;
  driver_binary_inc_refc(call_data->args);
  ErlDrvPort port = dd->port;
  intptr_t port_ptr = (intptr_t) port;
  unsigned int thread_key = port_ptr;
  driver_async(dd->port, &thread_key, (asyncfun) run_js, (void *) call_data, NULL);

  driver_free(command);
}

static void
ready_async(ErlDrvData handle, ErlDrvThreadData async_data)
{
  perl_drv_t *dd = (perl_drv_t *) handle;
  perl_call *call_data = (perl_call *) async_data;

  erl_drv_output_term(driver_mk_port(dd->port),
                   call_data->return_terms, call_data->return_term_count);

  driver_free_binary(call_data->args);

  if (call_data->return_string != NULL) {
    driver_free((void *) call_data->return_string);
  }
  driver_free(call_data);
}

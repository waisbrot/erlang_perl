/* author Kevin Smith <ksmith@basho.com>
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
extern char **environ;

EXTERN_C void boot_DynaLoader (pTHX_ CV* cv);

void
xs_init(pTHX)
{
    char *file = __FILE__;
    dXSUB_SYS;

    newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
}

typedef struct _perl_drv_t {
  ErlDrvPort port;
  PerlInterpreter *vm;
  ErlDrvTermData atom_ok;
  ErlDrvTermData atom_error;
  ErlDrvTermData atom_unknown_cmd;
  int shutdown;
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
    NULL,                             /* finish */
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
  driver_output_term(dd->port, terms, sizeof(terms) / sizeof(terms[0]));
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

char *sm_eval(PerlInterpreter *vm, const char *filename, const char *code, int handle_retval) {
  char *retval = NULL;

  if (code == NULL) {
      return NULL;
  }

  //printf("Input: %s\n", code);

  PERL_SET_CONTEXT(vm);
  PL_exit_flags |= PERL_EXIT_DESTRUCT_END;

  SV* ret_sv = eval_pv(code, FALSE);
  if (SvTRUE(ERRSV))
  {
    printf("Error! %s\n", SvPV(ERRSV, PL_na));
  } else if (handle_retval) {
      if (handle_retval) {
          STRLEN len;
          char *xret = SvPV(ret_sv, len);
          retval = eperl_alloc(len);
          memcpy(retval, xret, len+1);
      }
  }

  return retval;
}

void run_js(void *jsargs) {
  perl_call *call_data = (perl_call *) jsargs;
  perl_drv_t *dd = call_data->driver_data;
  ErlDrvBinary *args = call_data->args;
  char *data = args->orig_bytes;
  char *command = read_command(&data);
  char *call_id = read_string(&data);
  char *result = NULL;
  if (strncmp(command, "ej", 2) == 0) {
    char *filename = read_string(&data);
    char *code = read_string(&data);
    result = sm_eval(dd->vm, filename, code, 1);
    if ((strncmp(result, "[{\"error\":\"notfound\"}]", 22) == 0) || (strncmp(result, "{\"error\"", 8) == 0)) {
        send_error_string_response(dd, call_data, call_id, result);
    }
    else {
        send_string_response(dd, call_data, call_id, result);
    }
    driver_free(filename);
    driver_free(code);
  }
  else if (strncmp(command, "dj", 2) == 0) {
    char *filename = read_string(&data);
    char *code = read_string(&data);
    result = sm_eval(dd->vm, filename, code, 0);
    if (result == NULL) {
      send_ok_response(dd, call_data, call_id);
    }
    else {
      send_error_string_response(dd, call_data, call_id, result);
    }
    driver_free(filename);
    driver_free(code);
  }
  else if (strncmp(command, "sd", 2) == 0) {
    dd->shutdown = 1;
    send_ok_response(dd, call_data, call_id);
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
  char *argv[] = { };
  int argc = 0;
  PERL_SYS_INIT3(&argc,&argv, &environ);
  return 0;
}

static ErlDrvData start(ErlDrvPort port, char *cmd) {
  perl_drv_t *retval = eperl_alloc(sizeof(perl_drv_t));
  retval->port = port;
  retval->shutdown = 0;
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

void sm_shutdown(void) {
     printf("Shutdown\n");
     PERL_SYS_TERM();
}
void sm_stop(PerlInterpreter *vm) {
     printf("Stop\n");
     perl_destruct(vm);
     perl_free(vm);
}
static void stop(ErlDrvData handle) {
  perl_drv_t *dd = (perl_drv_t*) handle;
  if(dd->vm != NULL) {
    sm_stop(dd->vm);
  }
  if (dd->shutdown) {
    sm_shutdown();
  }
  driver_free(dd);
}

static void process(ErlDrvData handle, ErlIOVec *ev) {
  perl_drv_t *dd = (perl_drv_t *) handle;

  char *data = ev->binv[1]->orig_bytes;
  char *command = read_command(&data);
  if (strncmp(command, "ij", 2) == 0) {
    char *embedding[] = { "", "-MJSON::XS", "-e", "0" };
    char *call_id = read_string(&data);
    int thread_stack = read_int32(&data);
    if (thread_stack < 8) {
      thread_stack = 8;
    }
    thread_stack = thread_stack * (1024 * 1024);
    int heap_size = read_int32(&data) * (1024 * 1024);
    dd->vm = perl_alloc();
    perl_construct( dd->vm );
    perl_parse(dd->vm, xs_init, 4, embedding, NULL);
    eval_pv("$js_driver::json = JSON::XS->new->allow_nonref;", FALSE);
    if (SvTRUE(ERRSV))
    {
        printf("Error! %s\n", SvPV(ERRSV, PL_na));
    }

    send_immediate_ok_response(dd, call_id);
    driver_free(call_id);
  }
  else {
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
  }
  driver_free(command);
}

static void
ready_async(ErlDrvData handle, ErlDrvThreadData async_data)
{
  perl_drv_t *dd = (perl_drv_t *) handle;
  perl_call *call_data = (perl_call *) async_data;

  driver_output_term(dd->port,
                   call_data->return_terms, call_data->return_term_count);

  driver_free_binary(call_data->args);

  if (call_data->return_string != NULL) {
    driver_free((void *) call_data->return_string);
  }
  driver_free(call_data);
}

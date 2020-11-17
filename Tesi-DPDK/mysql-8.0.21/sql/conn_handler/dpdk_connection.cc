/*
   Copyright (c) 2013, 2019, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is also distributed with certain software (including
   but not limited to OpenSSL) that is licensed under separate terms,
   as designated in a particular file or component or in included license
   documentation.  The authors of MySQL hereby grant you an additional
   permission to link the program and your derivative works with the
   separately licensed software that they have included with MySQL.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
*/

#include "dpdk_connection.h"

#include <errno.h>

#include "channel_info.h"                // Channel_info
#include "connection_handler_manager.h"  // Connection_handler_manager
#include "init_net_server_extension.h"   // init_net_server_extension
#include "my_byteorder.h"
#include "my_shm_defaults.h"
#include "mysql/components/services/log_builtins.h"
#include "sql/log.h"
#include "sql/mysqld.h"  // connection_events_loop_aborted
#include "sql/psi_memory_key.h"
#include "sql/sql_class.h"  // THD
#include "violite.h"        // Vio

#define SEND_PORT 0
#define RECV_PORT 0

#define SEND_ADDR_IP "127.0.0.1"
#define RECV_ADDR_IP "127.0.0.1"

#define SEND_ADDR_MAC "02:00:00:00:00:01"
#define RECV_ADDR_MAC "02:00:00:00:00:01"

/*static const struct config_defaults defaults = {
    {
        RECV_ADDR_MAC,
        RECV_ADDR_IP,
        RECV_PORT,
    },
    {
        SEND_ADDR_MAC,
        SEND_ADDR_IP,
        SEND_PORT,
    },
};

struct config my_conf;*/

///////////////////////////////////////////////////////////////////////////
// Channel_info_dpdk implementation
///////////////////////////////////////////////////////////////////////////

/**
  This class abstracts the info. about the dpdk mode
  of communication with the server.
*/
class Channel_info_dpdk : public Channel_info {

 protected:
  virtual Vio *create_and_init_vio() const {
    Vio* vio = vio_new_dpdk();
    printf("VENGO CHIAMATA!\n");
    //vio->dpdk_config = my_conf;
    return vio;
  }

 public:

  Channel_info_dpdk(){}

  virtual THD *create_thd() {
    THD *thd = Channel_info::create_thd();

    if (thd != NULL) {
      init_net_server_extension(thd);
      thd->security_context()->set_host_ptr(my_localhost, strlen(my_localhost));
    }
    return thd;
  }

  virtual void send_error_and_close_channel(uint errorcode, int error,
                                            bool senderror) {
    Channel_info::send_error_and_close_channel(errorcode, error, senderror);

    if (!senderror) {

    }
  }
};

///////////////////////////////////////////////////////////////////////////
// DPDK_listener implementation
///////////////////////////////////////////////////////////////////////////

void DPDK_listener::close_dpdk() {
    /*chiude la connessione. Distrugge il listener
      creato nella setup_listener.
    */
}

bool DPDK_listener::setup_listener() { 

  /*devo inizializzare un listener. Devo dunque metter su
    un protocollo di comunicazione tra client e server in dpdk
    che mi permetta di instaurare la connessione.
  */
  //dpdk_initialization(&my_conf, &defaults);

  return false;
}

Channel_info *DPDK_listener::listen_for_connection_event() {

  /* fa partire la connessione. */

  Channel_info *channel_info = new (std::nothrow) Channel_info_dpdk();
  return channel_info;

}

void DPDK_listener::close_listener() { close_dpdk(); }

/*
* Copyright 2014 Chatsiri Rattana.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

/*  Titles			                                          Authors	         Date
 * 	- Call to server and scanning                         R.Chatsiri       25/09/2014
 * 	- Plan-00003 : Connect with RocksDB                   R.Chatsiri       25/09/2014
 */


#include "internet/scan_client/scan_client.hpp"
namespace internet
{

    namespace service
    {

        typename scan_client::MsgsRequestPointer scan_client::prepare_scan_request()
        {

            LOG(INFO)<<"-------------------------prepare_scan_request--------------------------";

            MsgsRequestPointer scan_request(new message_scan::RequestScan);
            //UUID per machine.
            scan_request->set_uuid(uuid);
            //Time from client.
            scan_request->set_timestamp(timestamp);
            //Scan data
            scan_request->set_type(message_scan::RequestScan::SCAN);

            scan_request->set_ip(std::string("127.0.0.1"));

            scan_request->set_conn_ip(std::string("127.0.0.1"));
            scan_request->set_conn_uuid(uuid);

            LOG(INFO)<<"Message type : " << scan_request->type();
            LOG(INFO)<<"Message scanning size : "<< fs_request_vec->size();
            LOG(INFO)<<"Client UUID : " << scan_request->uuid();

            typename std::vector<utils::file_scan_request *>::iterator iter_file;

            for(iter_file = fs_request_vec->begin();
                    iter_file != fs_request_vec->end();
                    ++iter_file) {

                message_scan::RequestScan::SetBinaryValue *request_set_binary =
                        new ::message_scan::RequestScan_SetBinaryValue;

                utils::file_scan_request *request = *iter_file;

                //binary file or MD5, SHA-256, SSDEPP.
                request_set_binary->set_binary(request->binary);

                //Scan type MD5, SHA-256, SSDEEP: ex : message_scan::RequestScan::MD5
                request_set_binary->set_scan_type(request->scan_type);

                //Scan file type: exe, elf and process.
                request_set_binary->set_file_type(request->file_type);

                request_set_binary->set_file_name(request->file_name);

                //File size
                request_set_binary->set_file_size(request->file_size);

                *scan_request->add_set_binary_value() = *request_set_binary;

                //File name
                LOG(INFO)<<"File Name : "<< request->file_name;
                LOG(INFO)<<"Binary    : "<< request->binary;
                LOG(INFO)<<"Scan type : "<< request->scan_type;

            }// for

            LOG(INFO)<<"--------------------------------------------------------------------";

            return scan_request;
        }

        //Send close uiid from client to server
        typename scan_client::MsgsRequestPointer scan_client::
					prepare_close_request(MsgsResponsePointer response_ptr)
        {

            LOG(INFO)<<"-------------------------prepare_close_request--------------------------";

            MsgsRequestPointer scan_request(new message_scan::RequestScan);
            //UUID per machine.
            scan_request->set_uuid(response_ptr->uuid());
            //Time from client.
            scan_request->set_timestamp(timestamp);
            //Scan data
            scan_request->set_type(message_scan::RequestScan::CLOSE_CONNECTION);

						//security reason : local IP
						scan_request->set_ip(response_ptr->ip());
						scan_request->set_uuid(response_ptr->uuid());

						//connection ip not encryption.
						scan_request->set_conn_ip(response_ptr->conn_ip());
						scan_request->set_conn_uuid(response_ptr->conn_uuid());

            LOG(INFO)<<"Message type : " << scan_request->type();
            LOG(INFO)<<"Message scanning size : "<< fs_request_vec->size();
            LOG(INFO)<<"Client UUID : " << scan_request->uuid();
						LOG(INFO)<<"Client IP   : " << scan_request->ip();
						LOG(INFO)<<"Client CONN UUID : " << scan_request->conn_uuid();
						LOG(INFO)<<"Client CONN IP   : " << scan_request->conn_ip();

            LOG(INFO)<<"--------------------------------------------------------------------";

            return scan_request;
        }

        //Send Request after connection with server.
        //[] Request and Sent Message scanning virus to server.
        //[] All data type group in message and sent to server.
        typename scan_client::MsgsRequestPointer  scan_client::prepare_regis_request()
        {

            LOG(INFO)<<"client : prepare_regis_request";

            MsgsRequestPointer start_request(new message_scan::RequestScan);
            //timestamp  from internal machine.
            start_request->set_timestamp(timestamp);

            start_request->set_type(message_scan::RequestScan::REGISTER);

            //security reason
            start_request->set_ip(std::string("127.0.0.1"));
            //create uuid on machine per file.
            start_request->set_uuid(uuid);

            start_request->set_conn_ip(std::string("127.0.0.1"));
            start_request->set_conn_uuid(uuid);

            return start_request;
        }


        //Received msgpack from server
        void scan_client::start_read_header(const boost::system::error_code& error)
        {
            try {
                msgs_read_buffer.resize(HEADER_SIZE);
                asio::async_read(msgs_socket, asio::buffer(msgs_read_buffer),
                        boost::bind(&scan_client::handle_read_header,
                                shared_from_this(),
                                asio::placeholders::error));

                LOG(INFO)<<"Client: start_read_header, Response, send to handle_read_header";

            } catch(boost::system::system_error& e) {
                LOG(INFO)<<"Client start_read_header, error : "<< e.code();
            }
        }

        void scan_client::handle_read_header(const boost::system::error_code& error)
        {
            LOG(INFO)<<"Client : handle_read_header";

            try {
                unsigned msgs_length =
                        msgs_packed_request_scan.decode_header(msgs_read_buffer);
                LOG(INFO)<<"Header message length : " << msgs_length;
                start_read_body(msgs_length);
            } catch(boost::system::system_error e) {
                LOG(INFO)<<"Client handle_read_header, error : "<< e.code();
            }
        }

        void scan_client::start_read_body(unsigned msgs_length)
        {
            LOG(INFO)<<"Client : start_read_body";
            msgs_read_buffer.resize(HEADER_SIZE + msgs_length);
            asio::mutable_buffers_1 buffer =
                    asio::buffer(&msgs_read_buffer[HEADER_SIZE], msgs_length);
            asio::async_read(msgs_socket, asio::buffer(buffer),
                    boost::bind(&scan_client::handle_read_body,
                            shared_from_this(),
                            asio::placeholders::error));
        }

        //[] Handle scan success.
        //[] Write result to database (RocksDB).
        //Plan-00004 : Client should register with uuid before scanning.
        void scan_client::handle_read_body(const boost::system::error_code& error)
        {
            LOG(INFO)<<"Client : handle_read_body";

            if(msgs_packed_response_scan.unpack(msgs_read_buffer)) {
                MsgsResponsePointer  response_ptr =
                        msgs_packed_response_scan.get_msg();

                LOG(INFO)<<"Clinet : Response back is type : " <<
                        response_ptr->type();

                switch(response_ptr->type()) {
                case  message_scan::ResponseScan::REGISTER_SUCCESS:
                    LOG(INFO)<<"Client : Register success";
                    //Get AES key and IV key from server.
                    //[] Setting key and IV for AES-128

                    LOG(INFO)<<"Fall back to Symmetric encryption key";

                    //Set ssl to null-encryption mode. Write AES-128 message to server.
                    SSL_set_cipher_list(msgs_socket.native_handle(), "eNULL");
                    SSL_set_options(msgs_socket.native_handle(), SSL_OP_NO_COMPRESSION);

                    //Prepare message before send scanning message to server.
                    do_write_scan_request(response_ptr);

                    break;

                    //[-] Handle case unsuccess after register
                case message_scan::ResponseScan::REGISTER_UNSUCCESS:
                    LOG(INFO)<<"Client : Register unusccess";
                    break;

                case message_scan::ResponseScan::SCAN_SUCCESS :
                    LOG(INFO)<<"Client : Scan success";
                    do_write_close_request(response_ptr);
                    break;

                    //[-] Handle case scan unsuccess
                case message_scan::ResponseScan::SCAN_UNSUCCESS :
                    LOG(INFO)<<"Client : Scan unsuccess";
                    break;

                case message_scan::ResponseScan::CLOSE_CONNECTION :
                    LOG(INFO)<<"Client : Close connection";

                    if(msgs_socket.lowest_layer().is_open()) {
                        msgs_socket.lowest_layer().close();
                        LOG(INFO)<<"Client : Close connection completed!";
                    }

                    break;

                default :
                    //Report before send to system.
                    LOG(INFO)<<"Client : Unknow message type(incident IP)";
                    break;
                }//switch type.


            }//if
        }// handle_read_body


        void scan_client::do_write_scan_request(MsgsResponsePointer  response_ptr)
        {
            try {
                LOG(INFO)<<"Client : do_write_scan_request, Response from Server-UUID : "
                        <<response_ptr->uuid();

                LOG(INFO)<<"Client : do_write_scan_request, Key from server : "
                        <<response_ptr->key();

                LOG(INFO)<<"Client : do_write_scan_request,  IV from server : "
                        <<response_ptr->iv();

                char *key_temp = new  char[response_ptr->key().size()+1];
                strcpy(key_temp, response_ptr->key().c_str());
                char *iv_temp  = new  char[response_ptr->iv().size()+1];
                strcpy(iv_temp, response_ptr->iv().c_str());

                unsigned char *key_external = reinterpret_cast<unsigned char *>(key_temp);

                unsigned char *iv_external = reinterpret_cast<unsigned char *>(iv_temp);

								LOG(INFO)<<"Key register : "<< key_external;
								LOG(INFO)<<"IV  register : "<< iv_external;

                internet::security::aes_cbc * aes_external =
                        new internet::security::aes_cbc(response_ptr->ip().c_str(),
                                response_ptr->uuid().c_str(),
                                key_external,
                                iv_external);


                enc_controller_->process_crypto(*aes_external, utils::register_key_crypto_mode);

                MsgsRequestPointer  scan_request = prepare_scan_request();

                //Encryption steps.
                secure_field_req->encryption(scan_request, enc_controller_);

                do_write_request(scan_request);
                LOG(INFO)<<"Client : do_write_scan_request, write scan request success";

            } catch(boost::system::system_error& error) {
                LOG(INFO)<<"Client : do_write_scan_request, error : " << error.code();
            }
        }//do_write_scan_request

        //[-] Write close scanning session on server.
        void scan_client::do_write_close_request(MsgsResponsePointer response_ptr)
        {
            try {

								secure_field_resp->decryption(response_ptr, enc_controller_);

                LOG(INFO)<<"Client : do_write_close_request, Response from Server-UUID : "
                        <<response_ptr->uuid();

                MsgsRequestPointer  close_request = prepare_close_request(response_ptr);

								secure_field_req->encryption(close_request, enc_controller_);

								LOG(INFO)<<"Client : Force close client, send request from IP : "<< close_request->ip();
                LOG(INFO)<<"Client : send request from UUID : "<< close_request->uuid();								
	
                do_write_request(close_request);

            } catch(boost::system::system_error& error) {
                LOG(INFO)<<"Client : do_write_close_request, error : "<< error.code();
            }

        }//do_write_close_request


        void scan_client::do_write_request(MsgsRequestPointer request)
        {
            try {

								LOG(INFO)<<"Client, do_write_request, start..";
								LOG(INFO)<<"Client, IP : " << request->ip();
								LOG(INFO)<<"Client, UUID : "<< request->uuid();

                std::vector<uint8_t> write_buffer;

                packedmessage_scan_client<message_scan::RequestScan>
                request_msgs(request);

                request_msgs.pack(write_buffer);

                msgs_socket.async_write_some(
                        asio::buffer(write_buffer, write_buffer.size())
                        ,boost::bind(&scan_client::start_read_header,
                                shared_from_this(),
                                asio::placeholders::error));

                LOG(INFO)<<"Client : do_write_request, Write request to server success.";

            } catch(boost::system::system_error& error) {
                LOG(INFO)<<"Client: do_write_request, error : " << error.code();
            }
        }//do_write_request

        void scan_client::on_connect(const boost::system::error_code& error)
        {
            LOG(INFO)<<"Client : on_connect, start scan";

            try {
                MsgsRequestPointer  request = prepare_regis_request();
                do_write_request(request);
            } catch(boost::system::system_error& err) {
                LOG(INFO)<<"Client : on_connection, error : "<< err.code();
            }

        }//on_connect

        void scan_client::start(std::string ip_addr,
                std::string port,
                std::vector<utils::file_scan_request *>&
                fs_request_vec)
        {
            try {

                set_file_scan(fs_request_vec);

                asio::ip::tcp::resolver::query query(ip_addr.c_str(), port.c_str());

                asio::ip::tcp::resolver::iterator iter_endpoint = resolver_.resolve(query);

                LOG(INFO)<<"Start verify cert ";

                /* Verify mode */
                msgs_socket.set_verify_mode(boost::asio::ssl::verify_peer);
                msgs_socket.set_verify_callback(boost::bind(&scan_client::verify_certificate,
                        this,
                        _1, _2));

                LOG(INFO)<<"Start Async connection";


                boost::asio::async_connect(msgs_socket.lowest_layer(),
                        iter_endpoint,
                        boost::bind(&scan_client::start_ssl_handshake,
                                shared_from_this(),
                                asio::placeholders::error));


            } catch(boost::system::system_error& error) {
                LOG(INFO)<< " Error " << error.code();
            }
        }//start

        bool scan_client::verify_certificate(bool preverified, asio::ssl::verify_context& ctx)
        {
            char subject_name[256];
            X509 *cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
            X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
            LOG(INFO)<<" Verifying cert name : " << std::string(subject_name);
            return preverified;
        }//verify_certificate


        void scan_client::start_ssl_handshake(const boost::system::error_code& error)
        {
            if(!error) {

                LOG(INFO)<<"Start SSL handshake";

                msgs_socket.async_handshake(asio::ssl::stream_base::client,
                        boost::bind(&scan_client::on_connect,
                                shared_from_this(),
                                boost::asio::placeholders::error));
            } else {
                LOG(INFO)<<" Error in start_ssl_handshake "<< error.message();
            }
        }//start SSL handshake

        //Default load system in client
        bool scan_client::load_system_engine()
        {

            //Crypto and Network Security
            LOG(INFO)<<"Client : Load security module.";

            /* Library threadsyncocl not deplay same load macro
            internet::security::get_encryption().reset(
            internet::security::create_encryption());

            if(internet::security::get_encryption().get() == NULL) {
            LOG(INFO)<<"System cannot initial encryption engine";
            return false;
            }

            enc_controller_ = internet::security::get_encryption()->get_encryption();

            if(enc_controller_ == NULL) {
            LOG(INFO)<<"Encryption controller cannot intial";
            return false;
            }

            */
            return true;
        }


    }//service


}

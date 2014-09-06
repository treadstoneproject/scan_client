#ifndef INTERNET_SCAN_CLIENT_HPP
#define INTERNET_SCAN_CLIENT_HPP
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
 *- Scan client service call to server scan file          R.Chatsiri
 */

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

#include <boost/lexical_cast.hpp>

//#include "internet/utils/common.hpp"
#include "utils/base/common.hpp"
#include "utils/uuid_generator.hpp"

#include "internet/logger/logging.hpp"

#include "internet/scan_client/packedmessage_scan_client.hpp"

#include "internet/scan_client/scan_dir.hpp"


namespace internet
{
    namespace asio = boost::asio;
    namespace service
    {

        class scan_client
        {

            public:

                typedef boost::shared_ptr<message_scan::RequestScan>
                MsgsRequestPointer;
                typedef boost::shared_ptr<message_scan::ResponseScan>
                MsgsResponsePointer;

                //sdir(io_service),// Scan dir : Plan-:00004, Initial service.

                scan_client(std::string ip_addr,
                        std::string port,
                        std::vector<utils::file_scan_request *> & fs_request_vec) :
                    msgs_socket(io_service), // Initial socket.
                    msgs_packed_request_scan(
                            boost::shared_ptr<message_scan::RequestScan>
                            (new message_scan::RequestScan())
                    ),
                    msgs_packed_response_scan(
                            boost::shared_ptr<message_scan::ResponseScan>
                            (new message_scan::ResponseScan())
                    ) {

										set_file_scan(fs_request_vec);
                    try {


                        int port_ = boost::lexical_cast<int>(port);
                        asio::ip::tcp::endpoint
                        endpoint(asio::ip::address::from_string(ip_addr),port_);
                        msgs_socket.async_connect(endpoint,
                                boost::bind(&scan_client::on_connect,this,
                                        asio::placeholders::error));

                        io_service.run();

                    } catch(boost::system::system_error& error) {
                        LOG(INFO)<< " Error " << error.code();
                    }

                }

                typename scan_client::MsgsRequestPointer prepare_start_request();

                void do_write_request(MsgsRequestPointer msgs_request);

                void on_connect(const boost::system::error_code& error);

                void start();
			
								//Read from server
								void start_read_header(const boost::system::error_code & error);
		
								void handle_read_header(const boost::system::error_code & error);

							  void start_read_body(unsigned msgs_length);

								void handle_read_body(const boost::system::error_code & error);

				
								//void prepare_request_scan(MsgsResponsePointer  response_ptr);

							  void on_scan(MsgsResponsePointer response_ptr);
									
                //Pre-process file detail.
                void set_file_scan(std::string file_path);

								typename scan_client::MsgsRequestPointer prepare_start_scan_request();

                typename scan_client::MsgsRequestPointer  prepare_scan_request();

								void on_write(const boost::system::error_code & error);


						  void on_read_register(const boost::system::error_code & error);

                //Set Data to message
                //UUID:
                //Timestamp :
                //Type : SCAN, REGISTER, RESULT
                //Binary data : e5949a143be892323217b183e13a8789bc328e
                //Scan type : message_scan::RequestScan::MD5
                //File type : message_scan::RequestScan::PE
                void set_uuid(std::string uuid) {
                    this->uuid = uuid;
                }

                void set_timestamp(std::string timestamp) {
                    this->timestamp = timestamp;
                }

                void set_file_scan(std::vector<utils::file_scan_request *>
                        & fs_request_vec) {
                    this->fs_request_vec = &fs_request_vec;
                }


            private:
								std::vector<uint8_t>  msgs_read_buffer;

                packedmessage_scan_client<message_scan::RequestScan>
                msgs_packed_request_scan;

                packedmessage_scan_client<message_scan::ResponseScan>
                msgs_packed_response_scan;

                MsgsRequestPointer scan_reqeust;
                //scan_dir sdir;

                std::string uuid;

                std::string timestamp;

                //utils::file_scan_request  * fs_reqeust;
                //utils::file_scan_response * fs_response;

                std::vector<utils::file_scan_request *> *fs_request_vec;

                uuid_generator uuid_gen;

                asio::io_service io_service;
                asio::ip::tcp::socket msgs_socket;
        };

    }

}



#endif /* INTERNET_SCAN_CLIENT_HPP */

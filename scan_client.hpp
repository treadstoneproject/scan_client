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
 *- Scan Plan-00003: Network management system.
 *                                                        R.Chatsiri
 */

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>

#include <boost/enable_shared_from_this.hpp>

#include <boost/lexical_cast.hpp>

#include "utils/base/common.hpp"
#include "utils/uuid_generator.hpp"

#include "internet/logger/logging.hpp"

#include "internet/scan_client/packedmessage_scan_client.hpp"

#include "internet/scan_client/scan_dir.hpp"

//Set Data to message
//UUID:
//Timestamp :
//Type : SCAN, REGISTER, RESULT
//Binary data : e5949a143be892323217b183e13a8789bc328e
//Scan type : message_scan::RequestScan::MD5
//File type : message_scan::RequestScan::PE


namespace internet
{
    namespace asio = boost::asio;

    namespace service
    {

        class scan_client : public boost::enable_shared_from_this<scan_client>
        {

            public:

                typedef boost::shared_ptr<message_scan::RequestScan>
                MsgsRequestPointer;
                typedef boost::shared_ptr<message_scan::ResponseScan>
                MsgsResponsePointer;

                typedef boost::shared_ptr<scan_client> scan_client_ptr;

                static scan_client_ptr start(asio::io_service& io_service,
                        std::string ip_addr,
                        std::string port,
                        std::vector<utils::file_scan_request *>&
                        fs_request_vec) {

                    scan_client_ptr new_(new scan_client(io_service));

                    new_->start(ip_addr, port, fs_request_vec);

                    return new_;

                }

                scan_client(asio::io_service& io_service) :
                    msgs_socket(io_service) { // Initial socket.

                    set_uuid(uuid_gen.generate());
                    set_timestamp(std::string("0:0:0:0"));


                }//scan_client

                void start(std::string ip_addr,
                        std::string port,
                        std::vector<utils::file_scan_request *>&
                        fs_request_vec);

                void start();

								//write register
                typename scan_client::MsgsRequestPointer prepare_regis_request();
								//write scan
                typename scan_client::MsgsRequestPointer  prepare_scan_request();
								//write close connection
								typename scan_client::MsgsRequestPointer prepare_close_request();

                //write request
                void do_write_request(MsgsRequestPointer msgs_request);

								//write scan 
                void do_write_scan_request(MsgsResponsePointer response_ptr);

                //write close connection
                void do_write_close_request(MsgsResponsePointer response_ptr);


                void on_connect(const boost::system::error_code& error);


                //Read from server
                void start_read_header(const boost::system::error_code& error);

                void handle_read_header(const boost::system::error_code& error);

                void start_read_body(unsigned msgs_length);

                void handle_read_body(const boost::system::error_code& error);

                //Pre-process file detail.
                void set_file_scan(std::string file_path);


                void set_uuid(std::string uuid) {
                    this->uuid = uuid;
                }

                void set_timestamp(std::string timestamp) {
                    this->timestamp = timestamp;
                }

                void set_file_scan(std::vector<utils::file_scan_request *>
                        & fs_request_vec) {

                    msgs_packed_request_scan =
                            boost::make_shared<message_scan::RequestScan>
                            (message_scan::RequestScan());

                    msgs_packed_response_scan =
                            boost::make_shared<message_scan::ResponseScan>
                            (message_scan::ResponseScan());

                    this->fs_request_vec = &fs_request_vec;
                }

                ~scan_client() {
                }


            private:
                std::vector<uint8_t>  msgs_read_buffer;

                packedmessage_scan_client<message_scan::RequestScan>
                msgs_packed_request_scan;

                packedmessage_scan_client<message_scan::ResponseScan>
                msgs_packed_response_scan;


                std::string uuid;

                std::string timestamp;

                std::vector<utils::file_scan_request *> *fs_request_vec;

                utils::uuid_generator uuid_gen;

                asio::ip::tcp::socket msgs_socket;
        };

    }

}



#endif /* INTERNET_SCAN_CLIENT_HPP */

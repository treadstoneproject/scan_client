#ifndef INTERNET_SERVICE_BASIC_SCAN_DIR_SERVICE_HPP
#define INTERNET_SERVICE_BASIC_SCAN_DIR_SERVICE_HPP

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
 * - Service scan directory in client.                    R.Chatsiri
 */

#include <boost/asio.hpp>
#include <boost/noncopyable.hpp>

#include "internet/scan_client/scan_dir_impl.hpp"


namespace internet
{

    namespace service
    {

        template<typename ScanDirImplementation = scan_dir_impl>
        class basic_scan_dir_service : public boost::asio::io_service::service
        {
            public:
                typedef boost::shared_ptr<ScanDirImplementation>  implementation_type;

                static boost::asio::io_service::id id;

                explicit basic_scan_dir_service(asio::io_service& io_service)
                    : boost::asio::io_service::service(io_service),
                      async_scan_dir_work_(new boost::asio::io_service::work(async_scan_dir_io_service_)),
                      async_scan_dir_thread_(
                              boost::bind(&boost::asio::io_service::run, &async_scan_dir_io_service_)) {

                }


                /**
                * @brief Send file to server scanning.
                *
                * @param impl  Impl call scan_dir_impl for invoke directory and file to server.
                */
                void construct(implementation_type& impl) {
                    impl.reset(new ScanDirImplementation());
                    impl->read_msg_scan();
                };

                void destroy(implementation_type&  impl) {
                    //impl->destroy();
                    //impl->reset();
                };


                void add_directory(implementation_type& impl,
                        const std::string& dir_name) {
                    impl->add_directory(dir_name);
                }

                /* Send Message file download https link  to server and received */
                template<typename Handler>
                class send_msgbuffer_handler
                {
                    public:
                        send_msgbuffer_handler(implementation_type& _impl,
                                asio::io_service _io_service,
                                Handler& _handler)
                            : impl_(_impl), // Call implementation class.
                              io_service_(_io_service),
                              work_(_io_service), // Guarantee start and stop service.
                              handler_(_handler) { }
                    private:
                        Handler handler_;

                        boost::weak_ptr<ScanDirImplementation> impl_;
                        boost::asio::io_service io_service_;
                        boost::asio::io_service::work work_;
                }; // end send_msgbuffer_handler


                /* Receive Message from server after download */
                template<typename Handler>
                class receive_msgbuffer_handler
                {

                    public:
                    private:

                };// end receive_msgbuffer_handler

            private:

                void shutdown_service() { };

                boost::asio::io_service async_scan_dir_io_service_;
                boost::scoped_ptr<boost::asio::io_service::work> async_scan_dir_work_;
                boost::thread async_scan_dir_thread_;
        }; //end  class basic_scan_dir

        template<typename ScanDirImplementation>
        boost::asio::io_service::id basic_scan_dir_service<ScanDirImplementation>::id;

        template class basic_scan_dir_service<scan_dir_impl>;

    }

}

#endif /* INTERNET_SERVICE_BASIC_SCAN_DIR_SERVICE_HPP */

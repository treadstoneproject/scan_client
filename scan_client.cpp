
#include "internet/scan_client/scan_client.hpp"
namespace internet
{

    namespace service
    {

        typename scan_client::MsgsRequestPointer scan_client::
        prepare_start_scan_request()
        {
						LOG(INFO)<<"Client : prepare_start_scan_request";

            MsgsRequestPointer scan_start_request(new message_scan::RequestScan);
            //UUID per machine.
            scan_start_request->set_uuid(uuid);
            //Time from client.
            scan_start_request->set_timestamp(timestamp);
            //Scan data
            scan_start_request->set_type(message_scan::RequestScan::SCAN);
            return scan_start_request;
        }

        typename scan_client::MsgsRequestPointer scan_client::prepare_scan_request()
        {
					  LOG(INFO)<<"Client : prepare_scan_request";

            MsgsRequestPointer scan_request(new message_scan::RequestScan);
            //UUID per machine.
            scan_request->set_uuid(uuid);
            //Time from client.
            scan_request->set_timestamp(timestamp);
            //Scan data
            scan_request->set_type(message_scan::RequestScan::SCAN);

            typename std::vector<utils::file_scan_request *>::iterator iter_file;

            LOG(INFO)<<"Message type : " << scan_request->type();
            LOG(INFO)<<"Message scanning size : "<< fs_request_vec->size();

            for(iter_file = fs_request_vec->begin();
                    iter_file != fs_request_vec->end();
                    ++iter_file) {

                message_scan::RequestScan::RequestSetBinaryValue *request_set_binary =
                        scan_request->add_request_set_binary_value();
                utils::file_scan_request *request = *iter_file;

                //binary file or MD5, SHA-256, SSDEPP.
                LOG(INFO)<<"Binary :" << request->binary;
                request_set_binary->set_binary(request->binary);

                //Scan type MD5, SHA-256, SSDEEP: ex : message_scan::RequestScan::MD5
                request_set_binary->set_scan_type(request->scan_type);

                //Scan file type: exe, elf and process.
                request_set_binary->set_file_type(request->file_type);

                //File name
                request_set_binary->set_file_name(request->file_name);

                //File size
                request_set_binary->set_file_size(request->file_size);

            }

            return scan_request;
        }

        //Send Request after connection with server.
        typename scan_client::MsgsRequestPointer  scan_client::prepare_start_request()
        {

            LOG(INFO)<<"client : prepare_start_request";

            MsgsRequestPointer start_request(new message_scan::RequestScan);

            set_uuid(uuid_gen.generate());
            set_timestamp(std::string("0:0:0:0"));

            //create uuid on machine per file.
            start_request->set_uuid(uuid);
            //timestamp  from internal machine.
            start_request->set_timestamp(timestamp);

            start_request->set_type(message_scan::RequestScan::REGISTER);

            return start_request;
        }

        void scan_client::on_read_register(const boost::system::error_code& error)
        {
						LOG(INFO)<<"Client : on_read_register ";
            if(!error) {
                start_read_header(error);
            }
        }

        void scan_client::on_write(const boost::system::error_code& error)
        {
						LOG(INFO)<<"Client : on_write ";

            if(!error) {
                MsgsRequestPointer  request = prepare_start_request();

                std::vector<uint8_t> write_buffer;

                packedmessage_scan_client<message_scan::RequestScan>
                request_msgs(request);

                request_msgs.pack(write_buffer);

                msgs_socket.async_write_some(
                        asio::buffer(write_buffer)
                        ,boost::bind(&scan_client::on_read_register,
                                this,
                                asio::placeholders::error));
                //Client received data from server.
            }
        }
        //Received msgpack from server
        void scan_client::start_read_header(const boost::system::error_code& error)
        {
            LOG(INFO)<<"Client: start_read_header";

            if(!error) {

                msgs_read_buffer.resize(HEADER_SIZE);
                asio::async_read(msgs_socket, asio::buffer(msgs_read_buffer),
                        boost::bind(&scan_client::handle_read_header, this,
                                asio::placeholders::error));

            }
        }

        void scan_client::handle_read_header(const boost::system::error_code& error)
        {
            LOG(INFO)<<"Client : handle_read_header";

            if(!error) {
                unsigned msgs_length =
                        msgs_packed_request_scan.decode_header(msgs_read_buffer);
                LOG(INFO)<<"Header message length : " << msgs_length;
                start_read_body(msgs_length);
            }
        }

        void scan_client::start_read_body(unsigned msgs_length)
        {
            LOG(INFO)<<"Client : start_read_body";
            msgs_read_buffer.resize(HEADER_SIZE + msgs_length);
            asio::mutable_buffers_1 buffer =
                    asio::buffer(&msgs_read_buffer[HEADER_SIZE], msgs_length);
            asio::async_read(msgs_socket, asio::buffer(buffer),
                    boost::bind(&scan_client::handle_read_body, this,
                            asio::placeholders::error));
        }

        void scan_client::handle_read_body(const boost::system::error_code& error)
        {
            LOG(INFO)<<"Client : handle_read_body";

            if(msgs_packed_response_scan.unpack(msgs_read_buffer)) {
                MsgsResponsePointer  response_ptr =
                        msgs_packed_response_scan.get_msg();

                LOG(INFO)<<"Clinet : Response back is type : " <<
                        response_ptr->type();

                if(response_ptr->type() ==
                        message_scan::ResponseScan::REGISTER_SUCCESS) {
                    LOG(INFO)<<"Client : Register success";
                    //Prepare message before send scanning message to server.
                    //prepare_request_scan(response_ptr);
                    on_scan(response_ptr);
                }
            }//if
        }

        void scan_client::prepare_request_scan(MsgsResponsePointer  response_ptr)
        {
            //Internal condition before scanning.
            on_scan(response_ptr);
        }// prepare_request_scan

        void scan_client::on_scan(MsgsResponsePointer  response_ptr)
        {
            LOG(INFO)<<"Client : on_scan, start scan";
						/*
            MsgsRequestPointer  request = prepare_start_scan_request();

            std::vector<uint8_t> write_buffer;

            packedmessage_scan_client<message_scan::RequestScan>
            request_msgs(request);

            request_msgs.pack(write_buffer);

            msgs_socket.async_write_some(
                    asio::buffer(write_buffer)
                    ,boost::bind(&scan_client::on_read_register,
                            this,
                            asio::placeholders::error));
					 */
        }//on scan

        void scan_client::do_write_request(MsgsRequestPointer request)
        {
            LOG(INFO)<<"Clinet : do_write_request, Write request to server ";

            std::vector<uint8_t> write_buffer;

            packedmessage_scan_client<message_scan::RequestScan>
            request_msgs(request);

            request_msgs.pack(write_buffer);

            msgs_socket.async_write_some(
                    asio::buffer(write_buffer)
                    ,boost::bind(&scan_client::on_write,
                            this,
                            asio::placeholders::error));
        }

        void scan_client::on_connect(const boost::system::error_code& error)
        {
            LOG(INFO)<<"Client : on_connect, start scan";

            if(!error) {
                try {
                    MsgsRequestPointer  request = prepare_start_request();
                    do_write_request(request);
                } catch(boost::system::system_error& err) {
                    LOG(INFO)<<"Client : on_scan, error : "<< err.code();
                }

            }

        }//on scan

    }


}

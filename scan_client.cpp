
#include "internet/scan_client/scan_client.hpp"
namespace internet
{

    namespace service
    {

        typename scan_client::MsgsRequestPointer scan_client::prepare_scan_request()
        {
            MsgsRequestPointer scan_request(new message_scan::RequestScan);
            //UUID per machine.
            scan_request->set_uuid(uuid);
            //Time from client.
            scan_request->set_timestamp(timestamp);
            //Scan data
            scan_request->set_type(message_scan::RequestScan::SCAN);

            typename std::vector<utils::file_scan_request *>::iterator iter_file;

            for(iter_file = fs_request_vec.begin();
                    iter_file != fs_request_vec.end();
                    ++iter_file) {

                message_scan::RequestScan::RequestSetBinaryValue *request_set_binary =
                        scan_request->mutable_request_set_binary_value(
                                iter_file - fs_request_vec.begin()
                        );
                utils::file_scan_request *request = *iter_file;
                //binary file or MD5, SHA-256, SSDEPP.
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
            MsgsRequestPointer start_request(new message_scan::RequestScan);
            //create uuid on machine per file.
            start_request->set_uuid(uuid);
            //timestamp  from internal machine.
            start_request->set_timestamp(timestamp);

            start_request->set_type(message_scan::RequestScan::REGISTER);

            return start_request;
        }

        void scan_client::do_write_request(MsgsRequestPointer request)
        {
            LOG(INFO)<<"client : Write request to server ";
            std::vector<uint8_t> write_buffer;

            packedmessage_scan_client<message_scan::RequestScan>
            request_msgs(request);

            request_msgs.pack(write_buffer);
            asio::write(msgs_socket, asio::buffer(write_buffer));
        }

        void scan_client::on_connect(const boost::system::error_code& error)
        {
            LOG(INFO)<<"Client : on_connect, start prepare request";

            if(!error) {
                MsgsRequestPointer request = prepare_start_request();
                //package message to
                do_write_request(request);
            }
        }

    }


}


#include "internet/scan_client/scan_client.hpp"
namespace internet
{

    namespace service
    {

        typename scan_client::MsgsRequestPointer scan_client::prepare_scan_request()
        {
            MsgsRequestPointer scan_request(new message_scan::RequestScan);
						//UUID per machine.
            scan_request->set_uuid("14ebc-7feb24af-fc38-44de-bc38");
            //Time from client.
            scan_request->set_timestamp("00:00:01");
						//binary file or MD5, SHA-256, SSDEPP.
            scan_request->request_set_binary_value->set_binary("e5949a143be892323217b183e13a8789bc328e");
            //Scan type MD5, SHA-256, SSDEEP
            scan_request->request_set_binary_value->set_scan_type(message_scan::RequestScan::MD5);
            //Scan file type: exe, elf and process.
            scan_request->request_set_binary_vlaue->set_file_type(message_scan::RequestScan::PE);
            return scan_request;
        }

        //Send Request after connection with server.
        typename scan_client::MsgsRequestPointer  scan_client::prepare_start_request()
        {
            MsgsRequestPointer start_request(new message_scan::RequestScan);
            //create uuid on machine per file.
            start_request->set_uuid("14ebc-7feb24af-fc38-44de-bc38");
            //timestamp  from internal machine.
            start_request->set_timestamp("00:00:01");

            start_request->set_request_type(message_scan::RequestType::REGISTER);

            return start_request;
        }

        void scan_client::do_write_request(MsgsRequestPointer request)
        {
            LOG(INFO)<<"client : Write request to server ";
            std::vector<uint8_t> write_buffer;
            packedmessage_scan_client<message_scan::RequestScan>  request_msgs(request);
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

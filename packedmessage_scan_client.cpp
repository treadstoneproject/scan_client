#include "internet/scan_client/packedmessage_scan_client.hpp"

namespace internet
{

    namespace service
    {

        template<typename MessageType>
        bool packedmessage_scan_client<MessageType>::pack(data_buffer& buffer)const
        {

            if(!msgs)
                return false;

            unsigned msg_size = msgs->ByteSize();
            buffer.resize(msg_size);
            //Included header file.
            encode_header(buffer, msg_size);
            return msgs->SerializeToArray(&buffer[HEADER_SIZE], msg_size);

        }


        template<typename MessageType>
        void packedmessage_scan_client<MessageType>::encode_header(data_buffer& buffer, unsigned size)const
        {

            if(buffer.size() >= HEADER_SIZE) {
                buffer[0] = static_cast<uint8_t>((size >> 24) & 0xFF);
                buffer[1] = static_cast<uint8_t>((size >> 16) & 0xFF);
                buffer[2] = static_cast<uint8_t>((size >> 8) & 0xFF);
                buffer[3] = static_cast<uint8_t>(size & 0xFF);

            }

            LOG(INFO)<<" Buffer header size more than header size ";

        }


        template class packedmessage_scan_client<message_scan::ResponseScan>;
        template class packedmessage_scan_client<message_scan::RequestScan>;


    }
}

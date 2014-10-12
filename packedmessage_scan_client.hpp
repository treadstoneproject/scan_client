#ifndef INTERNET_SERVICE_PACKEDMESSAGE_SCAN_CLIENT_HPP
#define INTERNET_SERVICE_PACKEDMESSAGE_SCAN_CLIENT_HPP

#include <stdlib.h>
#ifndef _MSC_VER
#include "stdint.h"   //Linux standard header.
#else
#include "utils/base/stdint_msvc.hpp" //VCpp supported header.
#endif

#define HEADER_SIZE 4

#include <boost/shared_ptr.hpp>

#include "internet/logger/logging.hpp"

#include "internet/msg/scan_server_client/message_scan.pb.h"

namespace internet
{

    namespace service
    {

        template<typename MessageType>
        class packedmessage_scan_client
        {

            public:

                typedef boost::shared_ptr<MessageType>  message_pointer;

                typedef std::vector<uint8_t> data_buffer;

                packedmessage_scan_client(message_pointer  msg = message_pointer())
                    : msgs(msg) { }


                bool pack(data_buffer& buffer)const;

                void encode_header(data_buffer& buffer, unsigned size)const;

                unsigned decode_header(const data_buffer& buffer)const;

                bool unpack(const data_buffer& buffer);

                message_pointer get_msg();

								~packedmessage_scan_client(){ }

            private:
                message_pointer msgs;
        };


    }


}


#endif /* INTERNET_SERVICE_PACKEDMESSAGE_SCAN_CLIENT_HPP */

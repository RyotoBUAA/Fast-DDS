// Copyright 2024 Proyectos y Sistemas de Mantenimiento SL (eProsima).
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*!
 * @file TestMessage.hpp
 * This header file contains the declaration of the described types in the IDL file.
 */

#ifndef _FAST_DDS_GENERATED_TESTMESSAGE_HPP_
#define _FAST_DDS_GENERATED_TESTMESSAGE_HPP_

#include <cstdint>
#include <string>
#include <vector>

/*!
 * @brief This class represents the structure SimpleTestMessage defined by the user in the IDL file.
 */
class SimpleTestMessage
{
public:
    SimpleTestMessage()
        : seq_num_(0)
        , data_type_(0)
    {
    }

    ~SimpleTestMessage() = default;

    SimpleTestMessage(const SimpleTestMessage& x) = default;
    SimpleTestMessage(SimpleTestMessage&& x) = default;
    SimpleTestMessage& operator=(const SimpleTestMessage& x) = default;
    SimpleTestMessage& operator=(SimpleTestMessage&& x) = default;

    void seq_num(uint32_t _seq_num)
    {
        seq_num_ = _seq_num;
    }

    uint32_t seq_num() const
    {
        return seq_num_;
    }

    uint32_t& seq_num()
    {
        return seq_num_;
    }

    void message(const std::string& _message)
    {
        message_ = _message;
    }

    void message(std::string&& _message)
    {
        message_ = std::move(_message);
    }

    const std::string& message() const
    {
        return message_;
    }

    std::string& message()
    {
        return message_;
    }

    void data_type(uint8_t _data_type)
    {
        data_type_ = _data_type;
    }

    uint8_t data_type() const
    {
        return data_type_;
    }

    uint8_t& data_type()
    {
        return data_type_;
    }

private:
    uint32_t seq_num_;
    std::string message_;
    uint8_t data_type_;
};

#endif // _FAST_DDS_GENERATED_TESTMESSAGE_HPP_


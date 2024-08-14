#pragma once

#include <stdint.h>
#include <stdio.h>

#include <string>

/// @file

class IDataContainer
{
public:
    virtual const uint8_t* getDataPtr(size_t offset = 0) const = 0;
    virtual ~IDataContainer() {}
};

/**
 * @class Layer
 * Layer базовый класс для протоколов. Данный класс предоставляет свойства и методы для доступа к
 * данным протокола и их редактированию.
 *
 * Каждый экземпляр протокола, является частью стека протоколов (который составляет пакет). Этот
 * стек протоколов возможно представить
 * в виде связанного списка, и каждый слой будет является элементом этого списка.
 * Класс Layer, как базовый класс, является абстрактным. Вот пример пакета, демонстрирующий эту
 * концепцию:
 *
  @verbatim

  ====================================================
  |Eth       |IPv4       |TCP       |Packet          |
  |Header    |Header     |Header    |Payload         |
  ====================================================

  |--------------------------------------------------|
  EthLayer data
             |---------------------------------------|
             IPv4Layer data
                         |---------------------------|
                         TcpLayer data
                                    |----------------|
                                    PayloadLayer data

  @endverbatim
 *
*/
class Layer : public IDataContainer
{
public:
    virtual ~Layer() = default;


    Layer* getNextLayer() const { return m_NextLayer; }
    Layer* getPrevLayer() const { return m_PrevLayer; }


    uint64_t getProtocol() const { return m_Protocol; }
    auto* getData() const { return m_Data; }


    size_t getDataLen() const { return m_DataLen; }
    auto* getLayerPayload() const { return m_Data + getHeaderLen(); }

    virtual size_t getLayerPayloadSize() const = 0;

    const uint8_t* getDataPtr(size_t offset = 0) const
    {
        return reinterpret_cast<const uint8_t*>(m_Data + offset);
    }

    virtual size_t getHeaderLen() const = 0;

protected:
    const uint8_t* m_Data;
    size_t m_DataLen;
    uint64_t m_Protocol;
    Layer* m_PrevLayer;
    Layer* m_NextLayer;

    Layer()
        : m_Data(nullptr), m_DataLen(0), m_Protocol(0), m_PrevLayer(nullptr), m_NextLayer(nullptr)
    {
    }

    Layer(const uint8_t* data, size_t dataLen, Layer* prevLayer, Layer* nextLayer)
        : m_Data(data)
        , m_DataLen(dataLen)
        , m_Protocol(0)
        , m_PrevLayer(prevLayer)
        , m_NextLayer(nextLayer)
    {
    }

    void setPrevLayer(Layer* prevLayer) { m_PrevLayer = prevLayer; }
    void setNextLayer(Layer* nextLayer) { m_NextLayer = nextLayer; }
};

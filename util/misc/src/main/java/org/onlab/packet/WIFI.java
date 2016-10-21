/**
*    Copyright 2012, Big Switch Networks, Inc.
*
*    Licensed under the Apache License, Version 2.0 (the "License"); you may
*    not use this file except in compliance with the License. You may obtain
*    a copy of the License at
*
*         http://www.apache.org/licenses/LICENSE-2.0
*
*    Unless required by applicable law or agreed to in writing, software
*    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
*    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
*    License for the specific language governing permissions and limitations
*    under the License.
**/

/**
 *
 */
package org.onlab.packet;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static com.google.common.base.MoreObjects.toStringHelper;
import static org.onlab.packet.PacketUtils.checkHeaderLength;
import static org.onlab.packet.PacketUtils.checkInput;

public class WIFI extends BasePacket {
    public static final short OP_ASSOCIATION_REQUEST = 0x0;
    public static final short OP_PROBE_REQUEST = 0x4;
    public static final short OP_PROBE_RESPONSE = 0x5;
    public static final short OP_BEACON = 0x8;
    public static final short OP_DISASSOCIATION_REQUEST = 0xa;
    public static final short MIN_HEADER_LENGTH = 18;

    protected byte[] dstMac;
    protected byte[] srcMac;
    protected byte[] bssidMac;
    protected byte[] reqId;
    protected byte[] ssidLen;
    protected byte[] ssidName;
    protected byte[] dataRatesLen;
    protected byte[] dataRates;
    protected byte[] dssetChannel;
    //protected byte[] body;

    public WIFI() {
        dstMac = new byte[6];
        srcMac = new byte[6];
        bssidMac = new byte[6];
        reqId = new byte[2];
        ssidLen = new byte[2];
        dataRatesLen = new byte[2];
        dssetChannel = new byte[3];
    }

    public byte getReqId() {
        return this.reqId[1];
    }

    public WIFI setReqId(byte reqId) {
        this.reqId[0] = 0;
        this.reqId[1] = reqId;
        return this;
    }

    public byte getdataRatesLen() {
        return this.dataRatesLen[1];
    }

    public WIFI setdataRatesLen(byte dataRatesLen) {
        this.dataRatesLen[0] = 0x1;
        this.dataRatesLen[1] = dataRatesLen;
        return this;
    }

    public byte getssidNameLen() {
        return this.ssidLen[1];
    }

    public WIFI setssidNameLen(byte ssidLen) {
        this.ssidLen[0] = 0;
        this.ssidLen[1] = ssidLen;
        return this;
    }

    public byte[] getssidName() {
        return this.ssidName;
    }

    public byte[] getdataRates() {
        return this.dataRates;
    }

    public WIFI setdataRates(byte[] dataRates) {
        this.dataRates = dataRates;
        return this;
    }

    public byte getChannel() {
        return this.dssetChannel[2];
    }

    public WIFI setChannelId(byte chId) {
        this.dssetChannel[0] = 0x3;
        this.dssetChannel[1] = 0x1;
        this.dssetChannel[2] = chId;
        return this;
    }

    public byte[] getSrcMac() {
        return this.srcMac;
    }

    public WIFI setSrcMac(byte[] srcMac) {
        this.srcMac = srcMac;
        return this;
    }

    public byte[] getDstMac() {
        return this.dstMac;
    }

    public WIFI setDstMac(byte[] dstMac) {
        this.dstMac = dstMac;
        return this;
    }

    public byte[] getBssidMac() {
        return this.bssidMac;
    }

    public WIFI setBssidMac(byte[] bssidMac) {
        this.bssidMac = bssidMac;
        return this;
    }

    @Override
    public byte[] serialize() {
        int length = 16 /* MacAddrs of dst(4), src and bssid */ + 2 /* reqId */
        + 3 /* ChId */ + getssidNameLen() + getdataRatesLen() + 4 /* Headers */;

        byte[] payloadData = null;
        if (this.payload != null) {
            payload.setParent(this);
            payloadData = payload.serialize();
            //length += payloadData.length;
        }

        byte[] data = new byte[length];
        ByteBuffer bb = ByteBuffer.wrap(data);
        bb.put(this.dstMac, 0, 4);
        bb.put(this.srcMac, 0, 6);
        bb.put(this.bssidMac, 0, 6);
        bb.put(this.reqId, 0, 2);
        bb.put(this.ssidLen, 0, 2);
        bb.put(this.ssidName, 0, this.getssidNameLen());
        bb.put(this.dataRatesLen, 0, 2);
        bb.put(this.dataRates, 0, this.getdataRatesLen());
        bb.put(this.dssetChannel, 0, 3);

        if (payloadData != null) {
            bb.put(payloadData);
        }

        return data;
    }

    @Override
    public IPacket deserialize(final byte[] data, final int offset,
                               final int length) {
        final ByteBuffer bb = ByteBuffer.wrap(data, offset, length);

        bb.get(this.dstMac, 0, 4);  // Change to 6 later.
        bb.get(this.srcMac, 0, 6);
        bb.get(this.bssidMac, 0, 6);
        bb.get(this.reqId, 0, 2);
        bb.get(this.ssidLen, 0, 2);
        this.ssidName = new byte[this.getssidNameLen()];
        bb.get(this.ssidName, 0, this.getssidNameLen());
        bb.get(this.dataRatesLen, 0, 2);
        this.dataRates = new byte[this.getdataRatesLen()];
        bb.get(this.dataRates, 0, this.getdataRatesLen());
        bb.get(this.dssetChannel, 0, 3);

        /* if (bb.hasRemaining()) {
            this.body = new Data();
            this.body = payload.deserialize(data, bb.position(), bb.limit() - bb.position());
            this.body.setParent(this);
        } */

        return this;
    }

    /**
     * Deserializer function for WiFi frames.
     *
     * @return deserializer function
     */
    public static Deserializer<WIFI> deserializer() {
        return (data, offset, length) -> {
            checkInput(data, offset, length, MIN_HEADER_LENGTH);

            WIFI wifi = new WIFI();
            final ByteBuffer bb = ByteBuffer.wrap(data, offset, length);

            // Check we have enough space for the addresses
            checkHeaderLength(length, MIN_HEADER_LENGTH + 19);

            bb.get(wifi.dstMac, 0, 4);  // Change to 6 later.
            bb.get(wifi.srcMac, 0, 6);
            bb.get(wifi.bssidMac, 0, 6);
            bb.get(wifi.reqId, 0, 2);
            bb.get(wifi.ssidLen, 0, 2);
            wifi.ssidName = new byte[wifi.getssidNameLen()];
            bb.get(wifi.ssidName, 0, wifi.getssidNameLen());
            bb.get(wifi.dataRatesLen, 0, 2);
            wifi.dataRates = new byte[wifi.getdataRatesLen()];
            bb.get(wifi.dataRates, 0, wifi.getdataRatesLen());
            bb.get(wifi.dssetChannel, 0, 3);

            return wifi;
        };
    }

    @Override
    public int hashCode() {
        final int prime = 263;
        int result = super.hashCode();
        result = prime * result + Arrays.hashCode(dstMac);
        result = prime * result + Arrays.hashCode(srcMac);
        result = prime * result + Arrays.hashCode(bssidMac);
        result = prime * result + Arrays.hashCode(reqId);
        result = prime * result + Arrays.hashCode(ssidLen);
        result = prime * result + Arrays.hashCode(ssidName);
        result = prime * result + Arrays.hashCode(dataRatesLen);
        result = prime * result + Arrays.hashCode(dataRates);
        result = prime * result + Arrays.hashCode(dssetChannel);
        return result;
    }


    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (!(obj instanceof WIFI)) {
            return false;
        }
        WIFI other = (WIFI) obj;

        if (!Arrays.equals(dstMac, other.dstMac)) {
            return false;
        }
        if (!Arrays.equals(srcMac, other.srcMac)) {
            return false;
        }
        if (!Arrays.equals(bssidMac, other.bssidMac)) {
            return false;
        }
        if (!Arrays.equals(reqId, other.reqId)) {
            return false;
        }
        if (!Arrays.equals(ssidName, other.ssidName)) {
            return false;
        }
        if (!Arrays.equals(dataRates, other.dataRates)) {
            return false;
        }
        if (dssetChannel != other.dssetChannel) {
            return false;
        }
        return true;
    }


    public String toString() {
        return toStringHelper(getClass())
            .add("RequestID: ", Arrays.toString(reqId))
            .add("DestMacAddr: ", Arrays.toString(dstMac))
            .add("SrcMacAddr: ", Arrays.toString(srcMac))
            .add("BSSIDMacAddr: ", Arrays.toString(bssidMac))
            .add("SSDINameLen: ",  Arrays.toString(ssidLen))
            .add("SSDIName: ",  Arrays.toString(ssidName))
            .add("DataRatesLen: ",  Arrays.toString(dataRatesLen))
            .add("DataRates: ",  Arrays.toString(dataRates))
            .add("ChannelInfo: ",  Arrays.toString(dssetChannel))
            .toString();
    }
}

package org.onosproject.msa;

import static com.google.common.base.Preconditions.checkNotNull;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.ArrayList;

public class Psap {
    private final Logger log = LoggerFactory.getLogger(getClass());

    private MacAddress psapMac;
    private MacAddress bssidMac;
    private ArrayList<String> ssidsList;
    private MacAddress staMac;
    private Ip4Address staIpAddr; // to be filled later
    private static ConcurrentMap<MacAddress, MacAddress> staPsapMap;

    Psap(MacAddress bssid, MacAddress stamac, ArrayList<String> ssids) {
        this.bssidMac = bssid;
        this.staMac = stamac;
        this.ssidsList = ssids;
    }

    public static MacAddress createPsapId(MacAddress bssid, MacAddress stamac) {
        Long l = (bssid.toLong() ^ stamac.toLong());
        MacAddress uniqmac = MacAddress.valueOf(l);

        return uniqmac;
    }

    public void addEntryinPsap(MacAddress stamac, MacAddress macentry) {
        checkNotNull(staPsapMap, "PSAP Hashmap is null");
        if (!staPsapMap.containsKey(staMac)) {
            this.psapMac = macentry;
            this.staMac = stamac;
            log.info("InfoSvr(addEntryinPsap): \nHost MAC = {}, \nPSAP = {}", this.staMac, this.psapMac);
            staPsapMap.put(this.staMac, this.psapMac);
        } else {
            MacAddress storedPsapMac = staPsapMap.get(stamac);
            log.info("InfoSvr:\nHostMAC ({}) already added. Mapped PSAPMAC = {}.", this.staMac, storedPsapMac);
        }
    }

    public MacAddress getPsapMac(MacAddress stamac) {
        checkNotNull(stamac);
        log.info("InfoSvr(getPsapMac): \nHost MAC = {}, \nPSAP = {}", this.staMac, this.psapMac);
        return staPsapMap.get(stamac);  // check against null while calling.
    }

    public MacAddress getStaMacFromPsapMac(MacAddress psapmac, MacAddress bssidmac) {
        checkNotNull(psapmac);
        checkNotNull(bssidmac);

        Long l = (bssidmac.toLong() ^ psapmac.toLong());
        log.info("InfoSvr(getStaMacFromPsapMac): \nPSAP = {}, \nBSSID = {}.", psapMac, bssidmac);

        MacAddress srcmac = MacAddress.valueOf(l);
        log.info("InfoSvr(getStaMacFromPsapMac): Extracted Host Mac = {} from PSAP.", srcmac);

        return srcmac;
    }

    public static void createPsapHashMap() {
        // make sure that no new staPsap should be created.
        staPsapMap = new ConcurrentHashMap<MacAddress, MacAddress>();
    }

    public static void clearPsapHashMap() {
        staPsapMap.clear();
    }

    public MacAddress getPsapMac() {
        return this.psapMac;
    }


    public MacAddress getStaMac() {
        return this.staMac;
    }

    public List<String> getListOfSsids() {
        return this.ssidsList;
    }

    public Psap setNewSsidInList(String ssid) {
        this.ssidsList.add(new String(ssid));
        return this;
    }

    // TODO: Add IP address get / set methods
}

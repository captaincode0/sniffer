/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package linuxsniffer;

import java.util.ArrayList;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

/**
 *
 * @author captaincode
 */
public class NetworkInterfaces {
    private List<PcapIf> alldevs;
    private StringBuilder errbuffer;
    
    public NetworkInterfaces(){
        this.alldevs = new ArrayList<PcapIf>();
        this.errbuffer = new StringBuilder();
    }

    public List<PcapIf> getAlldevs() {
        return alldevs;
    }

    public StringBuilder getErrbuffer() {
        return errbuffer;
    }
    
    public String[] pack(){
        int result = Pcap.findAllDevs(alldevs, errbuffer);
        
        if(result == Pcap.NOT_OK || alldevs.isEmpty()){
            System.err.printf("Cannot read the list of devices, error is %s", errbuffer.toString());
            return null;
        }
        String[] interfaces = new String[alldevs.size()];
        
        System.out.println("Interfaces found");
        
        for(int i=0; i<alldevs.size(); i++){
            PcapIf device = alldevs.get(i);
            String desc = (device.getDescription() != null)?device.getDescription():"No description";
            
            interfaces[i] = "Interface ["+String.valueOf(i)+"]: "+device.getName()+" ["+desc+"]";
            System.out.println(interfaces[i]);
        }
        
        return interfaces;
    }
}

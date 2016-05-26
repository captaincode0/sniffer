/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package linuxsniffer;
/**
 *
 * @author root
 */
public interface Capturable {
    public void capture(PacketCapture pcapture);
}

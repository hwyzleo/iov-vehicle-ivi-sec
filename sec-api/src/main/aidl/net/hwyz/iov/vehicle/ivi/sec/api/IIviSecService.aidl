// Contract of the vehicle device identity service (IVI-SEC-SPEC §4.1).
package net.hwyz.iov.vehicle.ivi.sec.api;

import net.hwyz.iov.vehicle.ivi.sec.api.CertificateInfo;
import net.hwyz.iov.vehicle.ivi.sec.api.DeviceToken;

interface IIviSecService {
    int getState();
    String getDeviceId();
    CertificateInfo getCertificateInfo();
    byte[] signNonce(in byte[] nonce);
    DeviceToken getDeviceToken(in String[] requestedScopes);
    void invalidateDeviceToken();
}

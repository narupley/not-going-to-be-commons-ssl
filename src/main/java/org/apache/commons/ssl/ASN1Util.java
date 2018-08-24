/*
 * $HeadURL: file:///opt/dev/not-yet-commons-ssl-SVN-repo/tags/commons-ssl-0.3.17/src/java/org/apache/commons/ssl/ASN1Util.java $
 * $Revision: 183 $
 * $Date: 2015-03-16 12:12:27 -0700 (Mon, 16 Mar 2015) $
 *
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.apache.commons.ssl;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;
import java.util.List;
import java.util.Vector;

import org.apache.commons.ssl.org.bouncycastle.asn1.ASN1Encodable;
import org.apache.commons.ssl.org.bouncycastle.asn1.ASN1InputStream;
import org.apache.commons.ssl.org.bouncycastle.asn1.ASN1Integer;
import org.apache.commons.ssl.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.apache.commons.ssl.org.bouncycastle.asn1.ASN1OctetString;
import org.apache.commons.ssl.org.bouncycastle.asn1.ASN1Sequence;
import org.apache.commons.ssl.org.bouncycastle.asn1.ASN1Set;
import org.apache.commons.ssl.org.bouncycastle.asn1.ASN1TaggedObject;
import org.apache.commons.ssl.org.bouncycastle.asn1.DERPrintableString;
import org.apache.commons.ssl.org.bouncycastle.asn1.DERSequence;
import org.apache.commons.ssl.org.bouncycastle.asn1.DERSet;
import org.apache.commons.ssl.org.bouncycastle.asn1.DERTaggedObject;
import org.apache.commons.ssl.org.bouncycastle.asn1.DLSequence;
import org.apache.commons.ssl.util.Hex;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 16-Nov-2005
 */
public class ASN1Util {
    public static boolean DEBUG = false;
    public final static BigInteger BIGGEST =
        new BigInteger(Integer.toString(Integer.MAX_VALUE));

    public static ASN1Structure analyze(byte[] asn1)
        throws IOException {
        ASN1InputStream asn = new ASN1InputStream(asn1);
        DLSequence seq = (DLSequence) asn.readObject();
        ASN1Structure pkcs8 = new ASN1Structure();
        ASN1Util.analyze(seq, pkcs8, 0);
        return pkcs8;
    }

    public static void main(String[] args) throws Exception {
        DEBUG = true;
        FileInputStream in = new FileInputStream(args[0]);
        byte[] bytes = Util.streamToBytes(in);
        List list = PEMUtil.decode(bytes);
        if (!list.isEmpty()) {
            bytes = ((PEMItem) list.get(0)).getDerBytes();
        }

        ASN1Structure asn1 = analyze(bytes);
        while (asn1.bigPayload != null) {
            System.out.println("------------------------------------------");
            System.out.println(asn1);
            System.out.println("------------------------------------------");
            asn1 = analyze(asn1.bigPayload);
        }
    }


    public static void analyze(ASN1Encodable seq, ASN1Structure pkcs8,
                               int depth) {
        String tag = null;
        if (depth >= 2) {
            pkcs8.derIntegers = null;
        }
        Enumeration en;
        if (seq instanceof DLSequence) {
            en = ((DLSequence) seq).getObjects();
        } else if (seq instanceof DERSet) {
            en = ((DERSet) seq).getObjects();
        } else if (seq instanceof DERTaggedObject) {
            DERTaggedObject derTag = (DERTaggedObject) seq;
            tag = Integer.toString(derTag.getTagNo());
            Vector v = new Vector();
            v.add(derTag.getObject());
            en = v.elements();
        } else {
            throw new IllegalArgumentException("DEREncodable must be one of: DLSequence, DERSet, DERTaggedObject");
        }
        while (en != null && en.hasMoreElements()) {
            ASN1Encodable obj = (ASN1Encodable) en.nextElement();
            if (!(obj instanceof ASN1Sequence) &&
                !(obj instanceof ASN1Set) &&
                !(obj instanceof ASN1TaggedObject)) {
                String str = obj.toString();
                String name = obj.getClass().getName();
                name = name.substring(name.lastIndexOf('.') + 1);
                if (tag != null) {
                    name = " [tag=" + tag + "] " + name;
                }
                for (int i = 0; i < depth; i++) {
                    name = "  " + name;
                }
                if (obj instanceof ASN1Integer) {
                    ASN1Integer dInt = (ASN1Integer) obj;
                    if (pkcs8.derIntegers != null) {
                        pkcs8.derIntegers.add(dInt);
                    }
                    BigInteger big = dInt.getValue();
                    int intValue = big.intValue();
                    if (BIGGEST.compareTo(big) >= 0 && intValue > 0) {
                        if (pkcs8.iterationCount == 0) {
                            pkcs8.iterationCount = intValue;
                        } else if (pkcs8.keySize == 0) {
                            pkcs8.keySize = intValue;
                        }
                    }
                    str = dInt.getValue().toString();
                } else if (obj instanceof ASN1ObjectIdentifier) {
                    ASN1ObjectIdentifier id = (ASN1ObjectIdentifier) obj;
                    str = id.getId();
                    pkcs8.oids.add(str);
                    if (pkcs8.oid1 == null) {
                        pkcs8.oid1 = str;
                    } else if (pkcs8.oid2 == null) {
                        pkcs8.oid2 = str;
                    } else if (pkcs8.oid3 == null) {
                        pkcs8.oid3 = str;
                    }
                } else {
                    pkcs8.derIntegers = null;
                    if (obj instanceof ASN1OctetString) {
                        ASN1OctetString oct = (ASN1OctetString) obj;
                        byte[] octets = oct.getOctets();
                        int len = Math.min(10, octets.length);
                        boolean probablyBinary = false;
                        for (int i = 0; i < len; i++) {
                            byte b = octets[i];
                            boolean isBinary = b > 128 || b < 0;
                            if (isBinary) {
                                probablyBinary = true;
                                break;
                            }
                        }
                        if (probablyBinary && octets.length > 64) {
                            if (pkcs8.bigPayload == null) {
                                pkcs8.bigPayload = octets;
                            }
                            str = "probably binary";
                        } else {
                            str = Hex.encode(octets);
                            if (octets.length <= 64) {
                                if (octets.length % 8 == 0) {
                                    if (pkcs8.salt == null) {
                                        pkcs8.salt = octets;
                                    } else if (pkcs8.iv == null) {
                                        pkcs8.iv = octets;
                                    }
                                } else {
                                    if (pkcs8.smallPayload == null) {
                                        pkcs8.smallPayload = octets;
                                    }
                                }
                            }
                        }
                        str += " (length=" + octets.length + ")";
                    } else if (obj instanceof DERPrintableString) {
                        DERPrintableString dps = (DERPrintableString) obj;
                        str = dps.getString();
                    }
                }

                if (DEBUG) {
                    System.out.println(name + ": [" + str + "]");
                }
            } else {
                if (tag != null && DEBUG) {
                    String name = obj.getClass().getName();
                    name = name.substring(name.lastIndexOf('.') + 1);
                    name = " [tag=" + tag + "] " + name;
                    for (int i = 0; i < depth; i++) {
                        name = "  " + name;
                    }
                    System.out.println(name);
                }
                analyze(obj, pkcs8, depth + 1);
            }
        }
    }
}

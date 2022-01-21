// Copyright (c) 2021 The Trade Desk, Inc
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package com.uid2.attestation.gcp;

import com.uid2.enclave.AttestationException;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class VmidAttestationProviderTest  {
	@Test
	public void testAgainstDebugHttpServer() throws AttestationException {
		final VmidAttestationProvider provider = new VmidAttestationProvider();
		provider.setMetadataEndpoint("https://httpbin.org/get");
		byte[] output = provider.getAttestationRequest(new byte[] { 0x01, 0x02, 0x03 });
		String outputString = new String(output, StandardCharsets.US_ASCII);
		System.out.println(outputString);

		// base64 of 0x01 0x02 0x03 is AQID
		Assert.assertTrue(outputString.contains("audience=AQID"));
		Assert.assertTrue(outputString.contains("format=full"));
		Assert.assertTrue(outputString.contains("https://httpbin.org/get?"));
		Assert.assertTrue(outputString.contains("Metadata-Flavor"));
		Assert.assertTrue(outputString.contains("Google"));
	}
}

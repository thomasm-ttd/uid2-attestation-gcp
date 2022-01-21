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
import com.uid2.enclave.IAttestationProvider;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public class VmidAttestationProvider implements IAttestationProvider {
	// the url endpoint to send instance document request to
	private String metadataEndpoint = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity";

	@Override
	public byte[] getAttestationRequest(byte[] publicKey) throws AttestationException {
		// encode publicKey into base64 string and pass as audience
		String audience = Base64.getEncoder().encodeToString(publicKey);

		String instanceDocument = null;
		try {
			instanceDocument = obtainInstanceDocument(audience);
		} catch (IOException e) {
			throw new AttestationException(e);
		}
		return instanceDocument.getBytes(StandardCharsets.US_ASCII);
	}

	public void setMetadataEndpoint(String newEndpoint) {
		this.metadataEndpoint = newEndpoint;
	}

	private String obtainInstanceDocument(String audience) throws IOException {
		// curl -H "Metadata-Flavor: Google" \
		//   'http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience=$AUDIENCE&format=full'

		final String query = String.format("?audience=%s&format=full",
			URLEncoder.encode(audience, StandardCharsets.US_ASCII.toString()));

		final URL url = new URL(this.metadataEndpoint + query);
		final URLConnection conn = url.openConnection();
		conn.setRequestProperty("Metadata-Flavor", "Google");

		return readToEnd(conn.getInputStream());
	}

	private static String readToEnd(InputStream stream) throws IOException {
		final InputStreamReader reader = new InputStreamReader(stream);
		final char[] buff = new char[1024];
		final StringBuilder sb = new StringBuilder();
		for (int count; (count = reader.read(buff, 0, buff.length)) > 0;) {
			sb.append(buff, 0, count);
		}
		return sb.toString();
	}
}

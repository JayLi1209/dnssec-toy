pragma circom 2.2.3;

template AssertByte() {
    signal input in;
    signal output bits[8];

    var value = 0;
    for (var i = 0; i < 8; i++) {
        bits[i] <-- (in >> i) & 1;
        bits[i] * (bits[i] - 1) === 0;
        value += bits[i] * (1 << i);
    }
    in === value;
}

template TranscriptCommitment(maxBytes) {
    signal input artifactLen;
    signal input transcriptHashLimbs[4];
    signal input artifactBytes[maxBytes];
    signal output artifactCommitment;

    signal acc[5 + maxBytes];
    acc[0] <== artifactLen + 1;

    for (var limb = 0; limb < 4; limb++) {
        acc[limb + 1] <== acc[limb] * 257 + transcriptHashLimbs[limb] + 1;
    }

    component byteChecks[maxBytes];
    for (var i = 0; i < maxBytes; i++) {
        byteChecks[i] = AssertByte();
        byteChecks[i].in <== artifactBytes[i];
        acc[5 + i] <== acc[4 + i] * 257 + artifactBytes[i] + 1;
    }

    artifactCommitment <== acc[4 + maxBytes];
}

component main {public [artifactLen, transcriptHashLimbs]} = TranscriptCommitment(8192);

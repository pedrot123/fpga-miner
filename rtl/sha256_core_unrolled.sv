// Fully-unrolled, 64-stage pipelined SHA-256 block processor.
// One block accepted when ready=1/start=1. Latency: 65 cycles. Throughput: 1 block/clk (after pipeline fill).
`timescale 1ns/1ps
module sha256_core_unrolled (
    input  logic         clk,
    input  logic         rst_n,
    input  logic         start,
    input  logic [255:0] iv,       // initial hash values (big-endian words)
    input  logic [511:0] block,    // message block (big-endian)
    output logic         ready,
    output logic [255:0] digest,
    output logic         digest_valid
);
    // SHA-256 constants as function for tool compatibility
    function automatic logic [31:0] K(input logic [5:0] idx);
        case (idx)
            6'd0:  K = 32'h428a2f98;
            6'd1:  K = 32'h71374491;
            6'd2:  K = 32'hb5c0fbcf;
            6'd3:  K = 32'he9b5dba5;
            6'd4:  K = 32'h3956c25b;
            6'd5:  K = 32'h59f111f1;
            6'd6:  K = 32'h923f82a4;
            6'd7:  K = 32'hab1c5ed5;
            6'd8:  K = 32'hd807aa98;
            6'd9:  K = 32'h12835b01;
            6'd10: K = 32'h243185be;
            6'd11: K = 32'h550c7dc3;
            6'd12: K = 32'h72be5d74;
            6'd13: K = 32'h80deb1fe;
            6'd14: K = 32'h9bdc06a7;
            6'd15: K = 32'hc19bf174;
            6'd16: K = 32'he49b69c1;
            6'd17: K = 32'hefbe4786;
            6'd18: K = 32'h0fc19dc6;
            6'd19: K = 32'h240ca1cc;
            6'd20: K = 32'h2de92c6f;
            6'd21: K = 32'h4a7484aa;
            6'd22: K = 32'h5cb0a9dc;
            6'd23: K = 32'h76f988da;
            6'd24: K = 32'h983e5152;
            6'd25: K = 32'ha831c66d;
            6'd26: K = 32'hb00327c8;
            6'd27: K = 32'hbf597fc7;
            6'd28: K = 32'hc6e00bf3;
            6'd29: K = 32'hd5a79147;
            6'd30: K = 32'h06ca6351;
            6'd31: K = 32'h14292967;
            6'd32: K = 32'h27b70a85;
            6'd33: K = 32'h2e1b2138;
            6'd34: K = 32'h4d2c6dfc;
            6'd35: K = 32'h53380d13;
            6'd36: K = 32'h650a7354;
            6'd37: K = 32'h766a0abb;
            6'd38: K = 32'h81c2c92e;
            6'd39: K = 32'h92722c85;
            6'd40: K = 32'ha2bfe8a1;
            6'd41: K = 32'ha81a664b;
            6'd42: K = 32'hc24b8b70;
            6'd43: K = 32'hc76c51a3;
            6'd44: K = 32'hd192e819;
            6'd45: K = 32'hd6990624;
            6'd46: K = 32'hf40e3585;
            6'd47: K = 32'h106aa070;
            6'd48: K = 32'h19a4c116;
            6'd49: K = 32'h1e376c08;
            6'd50: K = 32'h2748774c;
            6'd51: K = 32'h34b0bcb5;
            6'd52: K = 32'h391c0cb3;
            6'd53: K = 32'h4ed8aa4a;
            6'd54: K = 32'h5b9cca4f;
            6'd55: K = 32'h682e6ff3;
            6'd56: K = 32'h748f82ee;
            6'd57: K = 32'h78a5636f;
            6'd58: K = 32'h84c87814;
            6'd59: K = 32'h8cc70208;
            6'd60: K = 32'h90befffa;
            6'd61: K = 32'ha4506ceb;
            6'd62: K = 32'hbef9a3f7;
            6'd63: K = 32'hc67178f2;
            default: K = 32'd0;
        endcase
    endfunction

    function automatic logic [31:0] rotr(input logic [31:0] x, input int n);
        rotr = (x >> n) | (x << (32 - n));
    endfunction

    function automatic logic [31:0] big_sigma0(input logic [31:0] x);
        big_sigma0 = rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    endfunction

    function automatic logic [31:0] big_sigma1(input logic [31:0] x);
        big_sigma1 = rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    endfunction

    function automatic logic [31:0] small_sigma0(input logic [31:0] x);
        small_sigma0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    endfunction

    function automatic logic [31:0] small_sigma1(input logic [31:0] x);
        small_sigma1 = rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    endfunction

    function automatic logic [31:0] Ch(input logic [31:0] x, input logic [31:0] y, input logic [31:0] z);
        Ch = (x & y) ^ (~x & z);
    endfunction

    function automatic logic [31:0] Maj(input logic [31:0] x, input logic [31:0] y, input logic [31:0] z);
        Maj = (x & y) ^ (x & z) ^ (y & z);
    endfunction

    // Latched message block and IV for stable pipeline operation
    logic [511:0] block_latched;
    logic [31:0]  iv_reg [0:7];

    // Message schedule (combinational from latched block)
    logic [31:0] w [0:63];
    always_comb begin
        for (int j = 0; j < 16; j++) w[j] = block_latched[511 - j*32 -: 32];
        for (int j = 16; j < 64; j++) w[j] = small_sigma1(w[j-2]) + w[j-7] + small_sigma0(w[j-15]) + w[j-16];
    end

    // Pipeline registers for state across 64 rounds
    logic [31:0] a [0:64];
    logic [31:0] b [0:64];
    logic [31:0] c [0:64];
    logic [31:0] d [0:64];
    logic [31:0] e [0:64];
    logic [31:0] f [0:64];
    logic [31:0] g [0:64];
    logic [31:0] h [0:64];

    logic [64:0] valid_pipe;
    logic        busy;

    assign ready = ~busy;

    // Stage 0 load
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            busy           <= 1'b0;
            valid_pipe     <= '0;
            block_latched  <= 512'd0;
            digest_valid   <= 1'b0;
            digest         <= 256'd0;
            for (int r = 0; r < 8; r++) begin
                iv_reg[r] <= 32'd0;
                a[0] <= 32'd0; // replicated below; just to avoid latches
            end
        end else begin
            digest_valid <= 1'b0;
            valid_pipe   <= {valid_pipe[63:0], (ready && start)};

            if (ready && start) begin
                block_latched <= block;
                {iv_reg[0], iv_reg[1], iv_reg[2], iv_reg[3], iv_reg[4], iv_reg[5], iv_reg[6], iv_reg[7]} <= iv;
                a[0] <= iv[255:224];
                b[0] <= iv[223:192];
                c[0] <= iv[191:160];
                d[0] <= iv[159:128];
                e[0] <= iv[127:96];
                f[0] <= iv[95:64];
                g[0] <= iv[63:32];
                h[0] <= iv[31:0];
                busy <= 1'b1;
            end else if (valid_pipe[64]) begin
                busy         <= 1'b0;
                digest_valid <= 1'b1;
                digest[255:224] <= iv_reg[0] + a[64];
                digest[223:192] <= iv_reg[1] + b[64];
                digest[191:160] <= iv_reg[2] + c[64];
                digest[159:128] <= iv_reg[3] + d[64];
                digest[127:96]  <= iv_reg[4] + e[64];
                digest[95:64]   <= iv_reg[5] + f[64];
                digest[63:32]   <= iv_reg[6] + g[64];
                digest[31:0]    <= iv_reg[7] + h[64];
            end
        end
    end

    // Round pipeline stages
    genvar i;
    generate
        for (i = 1; i <= 64; i = i + 1) begin : round_pipe
            wire [31:0] T1 = h[i-1] + big_sigma1(e[i-1]) + Ch(e[i-1], f[i-1], g[i-1]) + K(i-1) + w[i-1];
            wire [31:0] T2 = big_sigma0(a[i-1]) + Maj(a[i-1], b[i-1], c[i-1]);

            always_ff @(posedge clk or negedge rst_n) begin
                if (!rst_n) begin
                    a[i] <= 32'd0;
                    b[i] <= 32'd0;
                    c[i] <= 32'd0;
                    d[i] <= 32'd0;
                    e[i] <= 32'd0;
                    f[i] <= 32'd0;
                    g[i] <= 32'd0;
                    h[i] <= 32'd0;
                end else begin
                    a[i] <= T1 + T2;
                    b[i] <= a[i-1];
                    c[i] <= b[i-1];
                    d[i] <= c[i-1];
                    e[i] <= d[i-1] + T1;
                    f[i] <= e[i-1];
                    g[i] <= f[i-1];
                    h[i] <= g[i-1];
                end
            end
        end
    endgenerate
endmodule

// Iterative SHA-256 block processor (one 512-bit block -> 256-bit digest).
// Expects big-endian input words. Runs 64 rounds, one per clock.
`timescale 1ns/1ps
module sha256_core (
    input  logic         clk,
    input  logic         rst_n,
    input  logic         start,
    input  logic [255:0] iv,       // initial hash values
    input  logic [511:0] block,    // message block (big-endian)
    output logic         ready,
    output logic [255:0] digest,
    output logic         digest_valid
);
    // SHA-256 constants via function to keep tool compatibility
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

    logic [31:0] w [0:63];
    logic [31:0] a, b, c, d, e, f, g, h;
    logic [31:0] iv_latched [0:7];
    logic [6:0]  round;
    logic        busy;

    logic [31:0] wt;
    logic [31:0] a_next, b_next, c_next, d_next, e_next, f_next, g_next, h_next;
    logic [31:0] T1, T2;

    // Prepare next state combinationally
    always_comb begin
        wt = (round < 16) ? w[round] : small_sigma1(w[round-2]) + w[round-7] + small_sigma0(w[round-15]) + w[round-16];
        T1 = h + big_sigma1(e) + Ch(e, f, g) + K(round[5:0]) + wt;
        T2 = big_sigma0(a) + Maj(a, b, c);

        a_next = T1 + T2;
        b_next = a;
        c_next = b;
        d_next = c;
        e_next = d + T1;
        f_next = e;
        g_next = f;
        h_next = g;
    end

    integer i;
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            ready        <= 1'b1;
            digest_valid <= 1'b0;
            busy         <= 1'b0;
            round        <= 7'd0;
            digest       <= 256'd0;
            for (i = 0; i < 64; i++) w[i] <= 32'd0;
            {a, b, c, d, e, f, g, h} <= 256'd0;
            for (i = 0; i < 8; i++) iv_latched[i] <= 32'd0;
        end else begin
            digest_valid <= 1'b0;
            if (start && ready) begin
                ready  <= 1'b0;
                busy   <= 1'b1;
                round  <= 7'd0;
                // latch IV and block words
                for (i = 0; i < 8; i++) iv_latched[i] <= iv[255 - i*32 -: 32];
                for (i = 0; i < 16; i++) w[i] <= block[511 - i*32 -: 32];
                for (i = 16; i < 64; i++) w[i] <= 32'd0;
                {a, b, c, d, e, f, g, h} <= iv;
            end else if (busy) begin
                // perform round
                {a, b, c, d, e, f, g, h} <= {a_next, b_next, c_next, d_next, e_next, f_next, g_next, h_next};
                if (round >= 16) w[round] <= wt;

                if (round == 7'd63) begin
                    busy         <= 1'b0;
                    ready        <= 1'b1;
                    digest_valid <= 1'b1;
                    digest[255:224] <= iv_latched[0] + a_next;
                    digest[223:192] <= iv_latched[1] + b_next;
                    digest[191:160] <= iv_latched[2] + c_next;
                    digest[159:128] <= iv_latched[3] + d_next;
                    digest[127:96]  <= iv_latched[4] + e_next;
                    digest[95:64]   <= iv_latched[5] + f_next;
                    digest[63:32]   <= iv_latched[6] + g_next;
                    digest[31:0]    <= iv_latched[7] + h_next;
                end else begin
                    round <= round + 7'd1;
                end
            end
        end
    end
endmodule

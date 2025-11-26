// Bitcoin-style double SHA-256 for an 80-byte header.
// Consumes one header per start and returns final 256-bit digest.
`timescale 1ns/1ps
module sha256_double #(
    parameter bit USE_UNROLLED = 1'b0  // set to 0 to revert to iterative core
) (
    input  logic         clk,
    input  logic         rst_n,
    input  logic         start,
    input  logic [639:0] header,   // 80-byte header, big-endian
    output logic         ready,
    output logic [255:0] hash_out,
    output logic         hash_valid
);
    // Initial hash values (H0..H7)
    localparam logic [255:0] IV = {
        32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a,
        32'h510e527f, 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19
    };

    typedef enum logic [2:0] {IDLE, START1, WAIT1, START2, WAIT2, START3, WAIT3, DONE} state_t;
    state_t state, state_next;

    logic core_start;
    logic [511:0] block_data;
    logic [255:0] core_iv;
    logic [255:0] core_digest;
    logic core_ready, core_valid;

    logic [255:0] digest_after_block1;
    logic [255:0] digest_after_block2;

    generate
        if (USE_UNROLLED) begin : g_unrolled
            sha256_core_unrolled core (
                .clk(clk),
                .rst_n(rst_n),
                .start(core_start),
                .iv(core_iv),
                .block(block_data),
                .ready(core_ready),
                .digest(core_digest),
                .digest_valid(core_valid)
            );
        end else begin : g_iter
            sha256_core core (
                .clk(clk),
                .rst_n(rst_n),
                .start(core_start),
                .iv(core_iv),
                .block(block_data),
                .ready(core_ready),
                .digest(core_digest),
                .digest_valid(core_valid)
            );
        end
    endgenerate

    // Assemble the three blocks needed for double SHA.
    function automatic logic [511:0] block1_from_header(input logic [639:0] hdr);
        block1_from_header = hdr[639:128];
    endfunction

    function automatic logic [511:0] block2_from_header(input logic [639:0] hdr);
        logic [511:0] blk;
        blk               = 512'd0;
        blk[511:384]      = hdr[127:0];      // remaining 16 bytes of header
        blk[383]          = 1'b1;            // padding 0x80 bit
        blk[63:0]         = 64'd640;         // message length in bits
        block2_from_header = blk;
    endfunction

    function automatic logic [511:0] block3_from_digest(input logic [255:0] dgst);
        logic [511:0] blk;
        blk               = 512'd0;
        blk[511:256]      = dgst;
        blk[255]          = 1'b1;            // padding bit
        blk[63:0]         = 64'd256;         // 32 bytes * 8
        block3_from_digest = blk;
    endfunction

    // FSM to stream blocks through the core.
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state               <= IDLE;
            digest_after_block1 <= 256'd0;
            digest_after_block2 <= 256'd0;
            hash_out            <= 256'd0;
            hash_valid          <= 1'b0;
        end else begin
            state      <= state_next;
            hash_valid <= 1'b0;
            if (core_valid) begin
                case (state)
                    WAIT1: digest_after_block1 <= core_digest;
                    WAIT2: digest_after_block2 <= core_digest;
                    WAIT3: begin
                        hash_out   <= core_digest;
                        hash_valid <= 1'b1;
                    end
                    default: ;
                endcase
            end
        end
    end

    // control path
    always_comb begin
        core_start = 1'b0;
        core_iv    = IV;
        block_data = 512'd0;
        ready      = 1'b0;
        state_next = state;

        case (state)
            IDLE: begin
                ready = 1'b1;
                if (start) state_next = START1;
            end
            START1: begin
                block_data = block1_from_header(header);
                core_iv    = IV;
                if (core_ready) begin
                    core_start = 1'b1;
                    state_next = WAIT1;
                end
            end
            WAIT1: begin
                if (core_valid) state_next = START2;
            end
            START2: begin
                block_data = block2_from_header(header);
                core_iv    = digest_after_block1;
                if (core_ready) begin
                    core_start = 1'b1;
                    state_next = WAIT2;
                end
            end
            WAIT2: begin
                if (core_valid) state_next = START3;
            end
            START3: begin
                block_data = block3_from_digest(digest_after_block2);
                core_iv    = IV;
                if (core_ready) begin
                    core_start = 1'b1;
                    state_next = WAIT3;
                end
            end
            WAIT3: begin
                if (core_valid) state_next = DONE;
            end
            DONE: begin
                ready = 1'b1;
                if (!start) state_next = IDLE;
            end
            default: state_next = IDLE;
        endcase
    end
endmodule

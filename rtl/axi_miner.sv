// AXI4-Lite wrapper around a Bitcoin double SHA-256 engine.
// Register map (word addresses, 32-bit):
// 0x00..0x4C : HEADER[0..19] (80 bytes, big-endian words)
// 0x50       : CONTROL {bit0=start}
// 0x54       : STATUS  {bit0=ready, bit1=busy, bit2=hash_valid, bit3=found}
// 0x58..0x74 : TARGET[0..7] (256-bit comparison target, big-endian)
// 0x78..0x94 : HASH[0..7]   (latest hash result, big-endian, read-only)
`timescale 1ns/1ps
module axi_miner #(
    parameter integer C_S_AXI_DATA_WIDTH = 32,
    parameter integer C_S_AXI_ADDR_WIDTH = 8
) (
    input  logic                         S_AXI_ACLK,
    input  logic                         S_AXI_ARESETN,
    input  logic [C_S_AXI_ADDR_WIDTH-1:0] S_AXI_AWADDR,
    input  logic                         S_AXI_AWVALID,
    output logic                         S_AXI_AWREADY,
    input  logic [C_S_AXI_DATA_WIDTH-1:0] S_AXI_WDATA,
    input  logic [(C_S_AXI_DATA_WIDTH/8)-1:0] S_AXI_WSTRB,
    input  logic                         S_AXI_WVALID,
    output logic                         S_AXI_WREADY,
    output logic [1:0]                   S_AXI_BRESP,
    output logic                         S_AXI_BVALID,
    input  logic                         S_AXI_BREADY,
    input  logic [C_S_AXI_ADDR_WIDTH-1:0] S_AXI_ARADDR,
    input  logic                         S_AXI_ARVALID,
    output logic                         S_AXI_ARREADY,
    output logic [C_S_AXI_DATA_WIDTH-1:0] S_AXI_RDATA,
    output logic [1:0]                   S_AXI_RRESP,
    output logic                         S_AXI_RVALID,
    input  logic                         S_AXI_RREADY
);
    localparam integer ADDR_LSB         = $clog2(C_S_AXI_DATA_WIDTH/8);
    localparam integer OPT_MEM_ADDR_BITS = C_S_AXI_ADDR_WIDTH-ADDR_LSB;

    logic [C_S_AXI_ADDR_WIDTH-1:0] axi_awaddr;
    logic [C_S_AXI_ADDR_WIDTH-1:0] axi_araddr;
    logic aw_en;

    // storage
    logic [31:0] header_words [0:19];
    logic [31:0] target_words [0:7];
    logic [31:0] hash_words   [0:7];
    logic [31:0] control_reg;
    logic        start_req;

    logic        hash_flag;
    logic        found_flag;

    // AXI write address channel
    always_ff @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            S_AXI_AWREADY <= 1'b0;
            aw_en         <= 1'b0;
        end else begin
            if (!S_AXI_AWREADY && S_AXI_AWVALID && S_AXI_WVALID && !aw_en) begin
                S_AXI_AWREADY <= 1'b1;
                aw_en         <= 1'b1;
                axi_awaddr    <= S_AXI_AWADDR;
            end else if (S_AXI_BREADY && S_AXI_BVALID) begin
                aw_en      <= 1'b0;
                S_AXI_AWREADY <= 1'b0;
            end else begin
                S_AXI_AWREADY <= 1'b0;
            end
        end
    end

    // AXI write data channel
    always_ff @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            S_AXI_WREADY <= 1'b0;
        end else begin
            if (!S_AXI_WREADY && S_AXI_WVALID && S_AXI_AWVALID && !aw_en) begin
                S_AXI_WREADY <= 1'b1;
            end else begin
                S_AXI_WREADY <= 1'b0;
            end
        end
    end

    // Write response
    always_ff @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            S_AXI_BVALID <= 1'b0;
            S_AXI_BRESP  <= 2'b00;
        end else begin
            if (S_AXI_AWREADY && S_AXI_AWVALID && S_AXI_WREADY && S_AXI_WVALID && !S_AXI_BVALID) begin
                S_AXI_BVALID <= 1'b1;
                S_AXI_BRESP  <= 2'b00;
            end else if (S_AXI_BVALID && S_AXI_BREADY) begin
                S_AXI_BVALID <= 1'b0;
            end
        end
    end

    // AXI read address channel
    always_ff @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            S_AXI_ARREADY <= 1'b0;
            axi_araddr    <= {C_S_AXI_ADDR_WIDTH{1'b0}};
        end else begin
            if (!S_AXI_ARREADY && S_AXI_ARVALID) begin
                S_AXI_ARREADY <= 1'b1;
                axi_araddr    <= S_AXI_ARADDR;
            end else begin
                S_AXI_ARREADY <= 1'b0;
            end
        end
    end

    // AXI read data channel
    always_ff @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            S_AXI_RVALID <= 1'b0;
            S_AXI_RRESP  <= 2'b00;
        end else begin
            if (S_AXI_ARREADY && S_AXI_ARVALID && !S_AXI_RVALID) begin
                S_AXI_RVALID <= 1'b1;
                S_AXI_RRESP  <= 2'b00;
            end else if (S_AXI_RVALID && S_AXI_RREADY) begin
                S_AXI_RVALID <= 1'b0;
            end
        end
    end

    // Helper to apply byte enables
    function automatic logic [31:0] apply_wstrb(
        input logic [31:0] old,
        input logic [31:0] wdata,
        input logic [3:0]  wstrb
    );
        logic [31:0] tmp;
        begin
            tmp = old;
            if (wstrb[0]) tmp[7:0]   = wdata[7:0];
            if (wstrb[1]) tmp[15:8]  = wdata[15:8];
            if (wstrb[2]) tmp[23:16] = wdata[23:16];
            if (wstrb[3]) tmp[31:24] = wdata[31:24];
            apply_wstrb = tmp;
        end
    endfunction

    integer i;
    // Register writes and start handling
    always_ff @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            control_reg <= 32'd0;
            start_req   <= 1'b0;
            for (i = 0; i < 20; i++) header_words[i] <= 32'd0;
            for (i = 0; i < 8; i++) target_words[i] <= 32'hffff_ffff;
        end else begin
            // auto-clear start after issuing pulse
            if (start_req && miner_ready) begin
                start_req       <= 1'b0;
                control_reg[0]  <= 1'b0;
            end

            if (S_AXI_AWREADY && S_AXI_AWVALID && S_AXI_WREADY && S_AXI_WVALID) begin
                unique case (axi_awaddr[ADDR_LSB+OPT_MEM_ADDR_BITS-1:ADDR_LSB])
                    // header region 0x00..0x4C
                    6'h00, 6'h01, 6'h02, 6'h03, 6'h04, 6'h05, 6'h06, 6'h07,
                    6'h08, 6'h09, 6'h0A, 6'h0B, 6'h0C, 6'h0D, 6'h0E, 6'h0F,
                    6'h10, 6'h11, 6'h12, 6'h13: begin
                        int idx;
                        idx = axi_awaddr[ADDR_LSB+OPT_MEM_ADDR_BITS-1:ADDR_LSB];
                        header_words[idx] <= apply_wstrb(header_words[idx], S_AXI_WDATA, S_AXI_WSTRB);
                    end
                    // control at 0x50 -> word offset 0x14
                    6'h14: begin
                        control_reg <= apply_wstrb(control_reg, S_AXI_WDATA, S_AXI_WSTRB);
                        start_req   <= S_AXI_WDATA[0];
                    end
                    // target at 0x58..0x74 -> offsets 0x16..0x1D
                    6'h16,6'h17,6'h18,6'h19,6'h1A,6'h1B,6'h1C,6'h1D: begin
                        int idx;
                        idx = axi_awaddr[ADDR_LSB+OPT_MEM_ADDR_BITS-1:ADDR_LSB] - 6'h16;
                        target_words[idx] <= apply_wstrb(target_words[idx], S_AXI_WDATA, S_AXI_WSTRB);
                    end
                    default: ;
                endcase
            end
        end
    end

    // Read mux
    always_comb begin
        S_AXI_RDATA = 32'd0;
        unique case (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS-1:ADDR_LSB])
            // header words
            6'h00, 6'h01, 6'h02, 6'h03, 6'h04, 6'h05, 6'h06, 6'h07,
            6'h08, 6'h09, 6'h0A, 6'h0B, 6'h0C, 6'h0D, 6'h0E, 6'h0F,
            6'h10, 6'h11, 6'h12, 6'h13: begin
                int idx;
                idx        = axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS-1:ADDR_LSB];
                S_AXI_RDATA = header_words[idx];
            end
            // control
            6'h14: S_AXI_RDATA = control_reg;
            // status at 0x54 (0x15)
            6'h15: S_AXI_RDATA = {28'd0, found_flag, hash_flag, ~miner_ready, miner_ready};
            // target
            6'h16,6'h17,6'h18,6'h19,6'h1A,6'h1B,6'h1C,6'h1D: begin
                int idx;
                idx        = axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS-1:ADDR_LSB] - 6'h16;
                S_AXI_RDATA = target_words[idx];
            end
            // hash output at 0x78..0x94 offsets 0x1E..0x25
            6'h1E,6'h1F,6'h20,6'h21,6'h22,6'h23,6'h24,6'h25: begin
                int idx;
                idx        = axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS-1:ADDR_LSB] - 6'h1E;
                S_AXI_RDATA = hash_words[idx];
            end
            default: S_AXI_RDATA = 32'd0;
        endcase
    end

    // Hash engine
    logic [639:0] header_vec;
    logic [255:0] target_vec;
    logic [255:0] miner_hash;
    logic         miner_ready;
    logic         miner_hash_valid;

    always_comb begin
        header_vec = '0;
        for (int j = 0; j < 20; j++) header_vec[639 - j*32 -: 32] = header_words[j];
    end

    always_comb begin
        target_vec = '0;
        for (int j = 0; j < 8; j++) target_vec[255 - j*32 -: 32] = target_words[j];
    end

    sha256_double u_double (
        .clk(S_AXI_ACLK),
        .rst_n(S_AXI_ARESETN),
        .start(start_req && miner_ready),
        .header(header_vec),
        .ready(miner_ready),
        .hash_out(miner_hash),
        .hash_valid(miner_hash_valid)
    );

    // Capture hash and flags
    always_ff @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            hash_flag  <= 1'b0;
            found_flag <= 1'b0;
            for (i = 0; i < 8; i++) hash_words[i] <= 32'd0;
        end else begin
            if (miner_hash_valid) begin
                for (i = 0; i < 8; i++) hash_words[i] <= miner_hash[255 - i*32 -: 32];
                hash_flag  <= 1'b1;
                found_flag <= (miner_hash <= target_vec);
            end else if (start_req && miner_ready) begin
                hash_flag  <= 1'b0;
                found_flag <= 1'b0;
            end
        end
    end

    // start_req auto-clear handled above
endmodule

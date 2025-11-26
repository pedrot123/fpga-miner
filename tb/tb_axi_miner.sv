`timescale 1ns/1ps
module tb_axi_miner;
    logic clk = 0;
    logic rst_n = 0;

    always #5 clk = ~clk;

    // AXI-lite signals
    logic [7:0]  awaddr;
    logic        awvalid;
    logic        awready;
    logic [31:0] wdata;
    logic [3:0]  wstrb;
    logic        wvalid;
    logic        wready;
    logic [1:0]  bresp;
    logic        bvalid;
    logic        bready;
    logic [7:0]  araddr;
    logic        arvalid;
    logic        arready;
    logic [31:0] rdata;
    logic [1:0]  rresp;
    logic        rvalid;
    logic        rready;

    axi_miner dut (
        .S_AXI_ACLK(clk),
        .S_AXI_ARESETN(rst_n),
        .S_AXI_AWADDR(awaddr),
        .S_AXI_AWVALID(awvalid),
        .S_AXI_AWREADY(awready),
        .S_AXI_WDATA(wdata),
        .S_AXI_WSTRB(wstrb),
        .S_AXI_WVALID(wvalid),
        .S_AXI_WREADY(wready),
        .S_AXI_BRESP(bresp),
        .S_AXI_BVALID(bvalid),
        .S_AXI_BREADY(bready),
        .S_AXI_ARADDR(araddr),
        .S_AXI_ARVALID(arvalid),
        .S_AXI_ARREADY(arready),
        .S_AXI_RDATA(rdata),
        .S_AXI_RRESP(rresp),
        .S_AXI_RVALID(rvalid),
        .S_AXI_RREADY(rready)
    );

    task automatic axi_write(input [7:0] addr, input [31:0] data);
        begin
            @(posedge clk);
            awaddr  <= addr;
            awvalid <= 1'b1;
            wdata   <= data;
            wstrb   <= 4'hF;
            wvalid  <= 1'b1;
            bready  <= 1'b1;
            wait (awready && wready);
            @(posedge clk);
            awvalid <= 1'b0;
            wvalid  <= 1'b0;
            wait (bvalid);
            @(posedge clk);
            bready  <= 1'b0;
        end
    endtask

    task automatic axi_read(input [7:0] addr, output [31:0] data);
        begin
            @(posedge clk);
            araddr  <= addr;
            arvalid <= 1'b1;
            rready  <= 1'b1;
            wait (arready);
            @(posedge clk);
            arvalid <= 1'b0;
            wait (rvalid);
            data = rdata;
            @(posedge clk);
            rready  <= 1'b0;
        end
    endtask

    localparam logic [255:0] EXPECTED = 256'h4be7570e8f70eb093640c8468274ba759745a7aa2b7d25ab1e0421b259845014;

    integer i;
    logic [31:0] rd;
    logic [255:0] hash_read;
    logic got_valid;

    initial begin
        awaddr  = 0; awvalid = 0; wdata = 0; wstrb = 0; wvalid = 0; bready = 0;
        araddr  = 0; arvalid = 0; rready = 0;
        hash_read = 0;

        repeat (4) @(posedge clk);
        rst_n = 1'b1;

        // Zero header
        for (i = 0; i < 20; i++) axi_write(i*4, 32'd0);
        // Target = max
        for (i = 0; i < 8; i++) axi_write(8'h58 + i*4, 32'hffff_ffff);

        // Start mining
        axi_write(8'h50, 32'h1);

        // Poll status for hash_valid bit2
        rd = 0;
        got_valid = 0;
        for (i = 0; (i < 500) && !got_valid; i++) begin
            axi_read(8'h54, rd);
            got_valid = rd[2];
            #1;
        end
        if (!got_valid) begin
            $fatal(1, "Timeout waiting for hash_valid");
        end

        // Read hash words
        for (i = 0; i < 8; i++) begin
            axi_read(8'h78 + i*4, rd);
            hash_read[255 - i*32 -: 32] = rd;
        end

        if (hash_read !== EXPECTED) begin
            $fatal(1, "AXI miner hash mismatch. Got %h expected %h", hash_read, EXPECTED);
        end

        // Check found flag bit3
        axi_read(8'h54, rd);
        if (!rd[3]) begin
            $fatal(1, "Found flag not set for loose target.");
        end

        $display("PASS: AXI miner produced expected hash and set found flag.");
        #20;
        $finish;
    end
endmodule

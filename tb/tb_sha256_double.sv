`timescale 1ns/1ps
module tb_sha256_double;
    logic clk = 0;
    logic rst_n = 0;
    logic start;
    logic [639:0] header;
    logic ready;
    logic [255:0] hash_out;
    logic hash_valid;

    always #5 clk = ~clk;

    sha256_double dut (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .header(header),
        .ready(ready),
        .hash_out(hash_out),
        .hash_valid(hash_valid)
    );

    localparam logic [255:0] EXPECTED = 256'h4be7570e8f70eb093640c8468274ba759745a7aa2b7d25ab1e0421b259845014;

    initial begin
        start  = 0;
        header = 640'd0;

        repeat (4) @(posedge clk);
        rst_n = 1;

        wait (ready);
        @(posedge clk);
        start = 1;
        @(posedge clk);
        start = 0;

        wait (hash_valid);
        if (hash_out !== EXPECTED) begin
            $error("Double SHA mismatch. Got %h expected %h", hash_out, EXPECTED);
            $display("Debug first hash (after block2) %h midstate %h", dut.digest_after_block2, dut.digest_after_block1);
            $fatal;
        end else begin
            $display("PASS: double SHA matched expected value.");
        end
        #20;
        $finish;
    end
endmodule

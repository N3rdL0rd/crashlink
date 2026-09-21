// Fixture for benchmarks/control_flow.py::TimeShortCircuitChain. Twelve
// short-circuit `&&` links OR-ed together, mirroring
// tests/test_cf.py::test_short_circuit_chain_lifts_linearly - each link's
// "true" arm jumps to the shared bail-out tail while its "false" arm falls
// into the next link, so no link's arms post-dominate one another.
class BenchShortCircuitChain {
    static var sink:Int = 0;
    public static function main() { guard("a", "b", 1, 2, null); }
    static function guard(a:String, b:String, i:Int, j:Int, o:Dynamic):Int {
        if ((a == b && i < 1) || (b == "x" && j > 2) || (a != null && i != 3) || (o == null && j <= 4) || (a == "y" && i >= 5) || (b != null && j == 6) || (a != b && i > 7) || (b == "z" && j < 8) || (o != null && i <= 9) || (a == null && j >= 10) || (b != "w" && i == 11) || (a != "v" && j != 12)) {
            sink += 1;
            report("bail", a, b);
            return -1;
        }
        sink += 2;
        report("pass", b, a);
        return 1;
    }
    static function report(tag:String, x:String, y:String):Void {
        sink += tag.length + x.length + y.length;
    }
}

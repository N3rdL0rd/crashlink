class StaleFieldReRead {
    static var counter:Int = 0;

    static function bumpAndGet():Int {
        counter++;
        return counter;
    }

    static function main() {
        var arr = [bumpAndGet(), bumpAndGet(), bumpAndGet()];
        Sys.println(arr.join(","));

        var o = new Holder();
        Sys.println(o.val + "," + o.val + "," + o.val);
        o.mutate();
        Sys.println(o.val + "," + o.val);

        var s = "" + counter + counter + counter;
        Sys.println(s);
        counter = 50;
        Sys.println("" + counter);
    }
}

class Holder {
    public var val:Int;
    public function new() { val = 1; }
    public function mutate():Void { val = val + 100; }
}

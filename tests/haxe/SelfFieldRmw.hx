class SelfFieldRmw {
    var x:Int;

    function new(x:Int) {
        this.x = x;
    }

    function compute():Int {
        this.x = this.x + 1;
        return this.x * 2;
    }

    function tick() {
        this.x = this.x + this.compute();
    }

    static function main() {
        var o = new SelfFieldRmw(5);
        o.tick();
        Sys.println(o.x);
    }
}

class CtorClosureThis {
    var name: String;
    var fn: Void -> String;

    public function new(n: String) {
        this.name = n;
        this.fn = function() {
            return "ctor:" + this.name;
        };
    }

    public function regular(): Void -> String {
        return function() {
            return "reg:" + this.name;
        };
    }

    static function main() {
        var a = new CtorClosureThis("A");
        var b = new CtorClosureThis("B");
        Sys.println(a.fn());
        Sys.println(b.fn());
        var f = a.regular();
        Sys.println(f());
        a.name = "A2";
        Sys.println(a.fn());
        Sys.println(f());
    }
}

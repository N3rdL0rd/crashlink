class Base {
    var label: String;
    public function new(label: String) {
        this.label = label;
    }
    public function describe(): String {
        return "Base:" + label;
    }
}
class Derived extends Base {
    public function new(label: String) {
        super(label);
    }
    public override function describe(): String {
        return super.describe() + "/Derived";
    }
}
class SuperCallCase {
    static function main() {
        var d = new Derived("x");
        trace(d.describe());
    }
}

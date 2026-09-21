// Shapes where HL routes a value through a scratch register that the
// decompiler should fold away: a lazily-initialised field, a nullable field
// defaulted in place, and a call result consumed by the next statement.
class TempHolder {
    public var levelData:Map<String, Dynamic>;
    public var currentTime:Null<Int>;
    public function new() {}
    public function compute():Int {
        return 7;
    }
}

class TempInline {
    static var sink:Int = 0;

    static function storeNew(h:TempHolder):Void {
        if (h.levelData == null) {
            h.levelData = new Map<String, Dynamic>();
        }
    }

    static function defaultField(h:TempHolder):Void {
        if (h.currentTime == null) {
            h.currentTime = 1;
        }
    }

    static function callIntoField(h:TempHolder):Void {
        sink = h.compute();
    }

    static function callIntoElement(h:TempHolder, out:Array<Int>):Void {
        out[0] = h.compute();
    }

    public static function main() {
        var h = new TempHolder();
        storeNew(h);
        defaultField(h);
        callIntoField(h);
        var out = [0];
        callIntoElement(h, out);
        Sys.println(sink + out[0]);
    }
}

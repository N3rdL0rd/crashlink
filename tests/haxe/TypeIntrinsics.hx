import hl.Type;

class TypeIntrinsics {
    static function main() {
        var v:Dynamic = "hello";
        var t = Type.getDynamic(v);
        if (t.kind == HObj) {
            trace("object");
        } else {
            trace("not object");
        }
    }
}

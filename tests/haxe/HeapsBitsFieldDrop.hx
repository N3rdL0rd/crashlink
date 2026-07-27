class BitsInput {
    public var nbits:Int;
    public var pos:Int;
    public function new() {
        nbits = 0;
        pos = 0;
    }
    public function readBits(n:Int):Int {
        pos += n;
        return n;
    }
}

class Src {
    var data:Array<Int>;
    var pos:Int = 0;
    public function new(data:Array<Int>) {
        this.data = data;
    }
    public function readByte():Int {
        if (pos >= data.length) throw "eof";
        var b = data[pos];
        pos++;
        return b;
    }
}

class HeapsBitsFieldDrop {
    var i:Src;
    var bits:BitsInput;
    var any_read:Bool;

    function new(data:Array<Int>) {
        i = new Src(data);
        bits = new BitsInput();
        any_read = false;
    }

    function skipID3v2() {
        i.readByte();
        i.readByte();
    }

    public function seekFrame():Int {
        var b = 0;
        var found = false;
        try {
            while (true) {
                b = i.readByte();
                if (!any_read) {
                    any_read = true;
                    if (b == 73) {
                        b = i.readByte();
                        if (b == 68) {
                            b = i.readByte();
                            if (b == 51) {
                                skipID3v2();
                            }
                        }
                    }
                }
                if (b == 255) {
                    b = 0;
                    bits.nbits = b;
                    b = bits.readBits(3);
                    if (b == 7) {
                        found = true;
                        return 1;
                    }
                }
            }
        } catch (e:Dynamic) {
            return found ? 1 : 0;
        }
    }

    static function main() {
        var s = new HeapsBitsFieldDrop([1, 2, 73, 68, 51, 9, 255]);
        trace(s.seekFrame());
    }
}

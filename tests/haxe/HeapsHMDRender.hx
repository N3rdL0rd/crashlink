class Indexes {
    public var vbuf:Dynamic;
    public function new() vbuf = null;
    public function isDisposed() return vbuf == null;
}

class Geometry {
    public var indexCounts:Array<Int>;
    public function new(indexCounts:Array<Int>) this.indexCounts = indexCounts;
}

class Engine {
    public function new() {}
    public function renderIndexed(buffer:Dynamic, indexes:Indexes, triPos:Int, count:Int) {
        trace('renderIndexed triPos=$triPos count=$count');
    }
    public function renderMultiBuffers(formats:Dynamic, buffers:Dynamic, indexes:Indexes, triPos:Int, count:Int) {
        trace('renderMultiBuffers triPos=$triPos count=$count');
    }
}

class HeapsHMDRender {
    var curMaterial:Int;
    var indexes:Indexes;
    var buffers:Dynamic;
    var lods:Array<Geometry>;
    var indexesTriPos:Array<Int>;
    var formats:Dynamic;
    var buffer:Dynamic;
    var data:Geometry;

    public function new(curMaterial:Int, data:Geometry, lods:Array<Geometry>, indexesTriPos:Array<Int>) {
        this.curMaterial = curMaterial;
        this.data = data;
        this.lods = lods;
        this.indexesTriPos = indexesTriPos;
        this.indexes = null;
        this.buffers = null;
        this.formats = null;
        this.buffer = null;
    }

    function alloc(engine:Engine) {
        indexes = new Indexes();
        indexes.vbuf = "allocated";
    }

    function baseRender(engine:Engine) {
        trace("base render (no material)");
    }

    public function render(engine:Engine) {
        if (curMaterial < 0) {
            baseRender(engine);
            return;
        }

        var materialCount = data.indexCounts.length;
        var lodLevel = Std.int(curMaterial / data.indexCounts.length);

        if (indexes == null || indexes.isDisposed())
            alloc(engine);
        if (buffers == null)
            engine.renderIndexed(buffer, indexes, indexesTriPos[curMaterial], Std.int(lods[lodLevel].indexCounts[curMaterial % materialCount] / 3));
        else
            engine.renderMultiBuffers(formats, buffers, indexes, indexesTriPos[curMaterial], Std.int(lods[lodLevel].indexCounts[curMaterial % materialCount] / 3));
        curMaterial = -1;
    }

    static function main() {
        var data = new Geometry([3, 6, 9]);
        var lods = [new Geometry([3, 6, 9])];
        var m = new HeapsHMDRender(1, data, lods, [0, 3, 6]);
        var engine = new Engine();
        m.render(engine);
        m.curMaterial = 2;
        m.render(engine);
    }
}

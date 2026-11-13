const Applet = imports.ui.applet;
const PopupMenu = imports.ui.popupMenu;
const GLib = imports.gi.GLib;
const Mainloop = imports.mainloop;
const ByteArray = imports.byteArray;

const REFRESH_SECONDS = 30;

function runCommand(argv) {
    try {
        let [ok, out] = GLib.spawn_command_line_sync(argv);
        if (!ok) return "";
        return ByteArray.toString(out).trim();
    } catch (e) {
        return "";
    }
}

function getLocalIp() {
    let out = runCommand("sh -c \"ip route get 1.1.1.1 | awk '{print $7; exit}'\"");
    return out || "unknown";
}

function getGateway() {
    let out = runCommand("sh -c \"ip route show default | awk '{print $3; exit}'\"");
    return out || "unknown";
}

function getListeningPorts() {
    let out = runCommand("sh -c \"ss -tuln | awk 'NR>1 {print $1, $5}' | head -n 15\"");
    return out ? out.split("\n") : ["No listening ports found"];
}

class NetReconApplet extends Applet.TextIconApplet {

    constructor(orientation, panelHeight, instanceId) {
        super(orientation, panelHeight, instanceId);

        this.set_applet_icon_symbolic_name("network-wired-symbolic");
        this.set_applet_tooltip("NetRecon");

        this.menuManager = new PopupMenu.PopupMenuManager(this);
        this.menu = new Applet.AppletPopupMenu(this, orientation);
        this.menuManager.addMenu(this.menu);

        this._refresh();

        this._timer = Mainloop.timeout_add_seconds(REFRESH_SECONDS, () => {
            this._refresh();
            return true;
        });
    }

    _refresh() {
        let ip = getLocalIp();
        this.set_applet_label(ip);

        this.menu.removeAll();

        this.menu.addMenuItem(new PopupMenu.PopupMenuItem(`Local IP: ${ip}`, { reactive: false }));
        this.menu.addMenuItem(new PopupMenu.PopupMenuItem(`Gateway: ${getGateway()}`, { reactive: false }));
        this.menu.addMenuItem(new PopupMenu.PopupMenuSeparatorItem());
        this.menu.addMenuItem(new PopupMenu.PopupMenuItem("Listening ports:", { reactive: false }));

        for (let line of getListeningPorts()) {
            this.menu.addMenuItem(new PopupMenu.PopupMenuItem(`  ${line}`, { reactive: false }));
        }
    }

    on_applet_clicked() {
        this.menu.toggle();
    }

    on_applet_removed_from_panel() {
        if (this._timer) {
            Mainloop.source_remove(this._timer);
            this._timer = null;
        }
    }
}

function main(metadata, orientation, panelHeight, instanceId) {
    return new NetReconApplet(orientation, panelHeight, instanceId);
}
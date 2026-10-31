// mautg launcher window (JXA / Cocoa). Started by the launcher:
//   osascript -l JavaScript gui.js <state file> <title> <icon>
// The launcher writes the state as JSON to <state file>; this script polls it and prints
// user actions as lines on stdout: ready, start <port> <0|1 no-config> <cli options>, stop, restart <port> <0|1> <cli>, open, log,
// update, link, admin, exit.
ObjC.import('Cocoa');

var W = 380, H = 372;
var ID = { start: 1, stop: 2, restart: 3, open: 4, log: 5, exit: 6, update: 7, link: 8, admin: 9 };
var ui = {}, lastState = '', lastPortSeq = -1, win, delegate, portField, cliField, noCfgBox;

function emit(s) {
  var d = $(s + '\n').dataUsingEncoding($.NSUTF8StringEncoding);
  $.NSFileHandle.fileHandleWithStandardOutput.writeData(d);
}

function rect(x, y, w, h) { return $.NSMakeRect(x, H - y - h, w, h); } // y from the top

function label(txt, x, y, w, h) {
  var f = $.NSTextField.alloc.initWithFrame(rect(x, y, w, h));
  f.setStringValue($(txt));
  f.setBezeled(false);
  f.setDrawsBackground(false);
  f.setEditable(false);
  f.setSelectable(false);
  win.contentView.addSubview(f);
  return f;
}

function button(txt, id, x, y, w, h) {
  var b = $.NSButton.alloc.initWithFrame(rect(x, y, w, h));
  b.setTitle($(txt));
  b.setBezelStyle(1); // rounded
  b.setTarget(delegate);
  b.setAction('btn:');
  b.setTag(id);
  win.contentView.addSubview(b);
  return b;
}

function onButton(id) {
  var p = String(ObjC.unwrap(portField.stringValue)).replace(/\s+/g, '');
  var o = (noCfgBox.state ? '1' : '0') + ' ' + String(ObjC.unwrap(cliField.stringValue)).replace(/[\r\n]+/g, ' ').trim();
  switch (id) {
    case ID.start: emit('start ' + p + ' ' + o); break;
    case ID.restart: emit('restart ' + p + ' ' + o); break;
    case ID.stop: emit('stop'); break;
    case ID.open: emit('open'); break;
    case ID.log: emit('log'); break;
    case ID.exit: emit('exit'); break;
    case ID.update: emit('update'); break;
    case ID.link: emit('link'); break;
    case ID.admin: emit('admin'); break;
  }
}

function applyState(s) {
  ui.status.setStringValue($(s.status));
  ui.upd.setStringValue($(s.upd));
  ui.foot.setStringValue($(s.foot));
  ui.adm.setStringValue($(s.adm || '-'));
  ui.admin.setHidden(!s.admShow);
  ui.admin.setEnabled(!busy);
  var run = !!s.running, busy = !!s.busy;
  ui.start.setEnabled(!run && !busy);
  ui.stop.setEnabled(run && !busy);
  ui.restart.setEnabled(run && !busy);
  ui.open.setEnabled(run && !busy);
  ui.update.setHidden(!s.updShow);
  ui.update.setEnabled(!busy);
  if (s.portSeq !== lastPortSeq) { // the launcher changed the port
    lastPortSeq = s.portSeq;
    portField.setStringValue($(String(s.port)));
    cliField.setStringValue($(s.cli || ''));
    noCfgBox.setState(s.noCfg ? 1 : 0);
  }
}

function tick() {
  try {
    var raw = $.NSString.stringWithContentsOfFileEncodingError($(stateFile), $.NSUTF8StringEncoding, null);
    var txt = ObjC.unwrap(raw);
    if (!txt || txt === lastState) return;
    lastState = txt;
    applyState(JSON.parse(txt));
  } catch (e) { }
}

var stateFile = '';

function run(argv) {
  try { start(argv); } catch (e) { emit("error " + e); throw e; }
}

function start(argv) {
  stateFile = argv[0];
  var title = argv[1] || 'mautg';
  var icon = argv[2] || '';

  var app = $.NSApplication.sharedApplication;
  app.setActivationPolicy($.NSApplicationActivationPolicyRegular);

  ObjC.registerSubclass({
    name: 'MautgDelegate',
    superclass: 'NSObject',
    // no protocols: JXA would compare the method types with the protocol and refuse them
    methods: {
      'btn:': { types: ['void', ['id']], implementation: function (sender) {
        var t = sender.tag; if (typeof t === 'function') t = t.call(sender);
        onButton(Number(t));
      } },
      'tick:': { types: ['void', ['id']], implementation: function (t) { tick(); } },
      'windowShouldClose:': { types: ['bool', ['id']], implementation: function (w) { emit('exit'); return false; } },
      'applicationShouldTerminate:': { types: ['unsigned long', ['id']], implementation: function (a) { emit('exit'); return 0; } }
    }
  });
  delegate = $.MautgDelegate.alloc.init;
  app.setDelegate(delegate);

  if (icon) {
    try { app.setApplicationIconImage($.NSImage.alloc.initWithContentsOfFile($(icon))); } catch (e) { }
  }

  // titled | closable | miniaturizable, buffered
  win = $.NSWindow.alloc.initWithContentRectStyleMaskBackingDefer($.NSMakeRect(0, 0, W, H), 7, 2, false);
  win.setTitle($(title));
  win.setDelegate(delegate);
  win.setReleasedWhenClosed(false);

  label('Status:', 16, 18, 60, 18);
  ui.status = label('starting ...', 80, 18, 280, 18);
  label('Web port:', 16, 50, 60, 18);
  portField = $.NSTextField.alloc.initWithFrame(rect(80, 46, 70, 24));
  portField.setStringValue($('8081'));
  win.contentView.addSubview(portField);
  label('applied with Start / Restart', 160, 50, 210, 18);

  ui.start = button('Start', ID.start, 14, 86, 112, 30);
  ui.stop = button('Stop', ID.stop, 134, 86, 112, 30);
  ui.restart = button('Restart', ID.restart, 254, 86, 112, 30);
  ui.open = button('Open web GUI', ID.open, 14, 126, 112, 30);
  ui.logb = button('Console log', ID.log, 134, 126, 112, 30);
  ui.exit = button('Exit', ID.exit, 254, 126, 112, 30);

  noCfgBox = $.NSButton.alloc.initWithFrame(rect(16, 168, 260, 20));
  noCfgBox.setButtonType(3); // switch (checkbox)
  noCfgBox.setTitle($('Disable Def-Config'));
  win.contentView.addSubview(noCfgBox);

  label('CLI options:', 16, 206, 74, 18);
  cliField = $.NSTextField.alloc.initWithFrame(rect(92, 202, 272, 24));
  cliField.setStringValue($(''));
  win.contentView.addSubview(cliField);

  label('Update:', 16, 244, 60, 18);
  ui.upd = label('checking ...', 80, 244, 170, 18);
  ui.update = button('Update', ID.update, 254, 238, 112, 30);
  ui.update.setHidden(true);

  label('Admin:', 16, 284, 60, 18);
  ui.adm = label('-', 80, 284, 170, 18);
  ui.admin = button('Admin setup', ID.admin, 254, 278, 112, 30);
  ui.admin.setHidden(true);

  var sep = $.NSBox.alloc.initWithFrame(rect(16, 326, W - 32, 2));
  sep.setBoxType(2); // separator
  win.contentView.addSubview(sep);

  try { // the app icon (paw) in front of the version, like the Windows launcher
    var iv = $.NSImageView.alloc.initWithFrame(rect(16, 336, 20, 20));
    iv.setImage($.NSImage.alloc.initWithContentsOfFile($(icon)));
    win.contentView.addSubview(iv);
  } catch (e) { }
  ui.foot = label('mautg.py', 42, 338, 190, 18);
  var link = button('www.jeitler.cc', ID.link, 240, 336, 120, 20);
  link.setBordered(false);
  try {
    var attr = $.NSMutableAttributedString.alloc.initWithString($('www.jeitler.cc'));
    attr.addAttributeValueRange($.NSForegroundColorAttributeName, $.NSColor.systemBlueColor, $.NSMakeRange(0, 14));
    link.setAttributedTitle(attr);
  } catch (e) { }
  ui.link = link;

  tick();
  $.NSTimer.scheduledTimerWithTimeIntervalTargetSelectorUserInfoRepeats(0.3, delegate, 'tick:', null, true);

  win.center;
  win.makeKeyAndOrderFront(null);
  app.activateIgnoringOtherApps(true); // once, at the start only
  emit('ready');
  app.run;
}

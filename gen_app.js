// ************************************************************************
// 
// ************************************************************************
function insn_locate(dso_id, i)
{
	let block = prog.dso[dso_id].block;
	let loc = { found: false, dso_id: dso_id, block: '', i: 0 };
	
	if ((block.length < 1) || (i === -1))
		return loc;
	
	let b0 = 0;
	let b1 = block.length - 1;
	
	if (i < block[b0].base)
		return loc;
	if (i >= block[b1].base + block[b1].insn.length)
		return loc;
	
	if (i < block[b0].base + block[b0].insn.length) {
		loc.found = true;
		loc.block = b0;
		loc.i = i - block[b0].base;
		return loc;
	}

	if (i >= block[b1].base) {
		loc.found = true;
		loc.block = b1;
		loc.i = i - block[b1].base;
		return loc;
	}
	
	while (true) {
		let bm = Math.floor((b0 + b1) / 2);
		
		if (bm === b0)
			return loc;
		
		if (i < block[bm].base) {
			b1 = bm;
		} else if (i >= block[bm].base + block[bm].insn.length) {
			b0 = bm;
		} else {
			loc.found = true;
			loc.block = bm;
			loc.i = i - block[bm].base;
			return loc;
		}
	}
}

// ************************************************************************
// 
// ************************************************************************
function insn_locate_sym(dso_id, sym_id)
{
	let i = prog.dso[dso_id].sym[sym_id].insn;
	let block = prog.dso[dso_id].block;
	let loc = { found: false, exact: false,
		dso_id: dso_id, block: '', i: 0 };
	
	if (block.length < 1)
		return loc;
	
	let b0 = 0;
	let b1 = block.length - 1;
	
	if (i < block[b0].base) {
		if (block[b0].insn[0].sym_id === sym_id) {
			loc.found = true;
			loc.exact = false;
			loc.block = b0;
			loc.i = 0;
		}

		return loc;
	}
	
	if (i >= block[b1].base + block[b1].insn.length)
		return loc;
	
	if (i < block[b0].base + block[b0].insn.length) {
		loc.found = true;
		loc.exact = true;
		loc.block = b0;
		loc.i = i - block[b0].base;
		return loc;
	}

	if (i >= block[b1].base) {
		loc.found = true;
		loc.exact = true;
		loc.block = b1;
		loc.i = i - block[b1].base;
		return loc;
	}
	
	while (true) {
		let bm = Math.floor((b0 + b1) / 2);
		
		if (bm === b0) {
			if (block[b1].insn[0].sym_id === sym_id) {
				loc.found = true;
				loc.exact = false;
				loc.block = b1;
				loc.i = 0;
			}

			return loc;
		}
		
		if (i < block[bm].base) {
			b1 = bm;
		} else if (i >= block[bm].base + block[bm].insn.length) {
			b0 = bm;
		} else {
			loc.found = true;
			loc.exact = true;
			loc.block = bm;
			loc.i = i - block[bm].base;
			return loc;
		}
	}
}

// ************************************************************************
// 
// ************************************************************************
function insn_info(loc)
{
	let r = {
		foffs: 0, addr: 0,
		bin: [],
		sym_id: -1, func_id: -1, file_id: -1, line: 0, disc: 0,
		disasm: '?',
		target_insn: -1, hits: 0, flags: 0,
		
		found: false, dso_id: -1, block: '', i: 0,
		sym_str: '',
		func_str: '',
		file_str: '',
	};

	if (!loc.found)
		return r;
	
	for (f in loc)
		r[f] = loc[f];
	
	let dso = prog.dso[loc.dso_id];
	let insn = dso.block[loc.block].insn[loc.i];
	
	for (f in insn)
		r[f] = insn[f];
	
	if (insn.sym_id !== -1) {
		let sym = dso.sym[insn.sym_id];
		r.sym_str = sym.name;
		
		if (sym.multiple !== 0)
			r.sym_str += '@0x' + sym.addr.toString(16);
		
		r.sym_str += '+0x'
			+ (insn.foffs - sym.foffs).toString(16);
	} else {
		r.sym_str = '@' + insn.addr.toString(16);
	}
	
	if (insn.func_id !== -1) {
		let func = dso.func[insn.func_id];
		r.func_str = func.name + '()';
	}
	
	if (insn.file_id !== -1) {
		let file = dso.file[insn.file_id];
		r.file_str = file.name + ':'
			+ insn.line;
		if (insn.disc !== 0)
			r.file_str += ' (discriminator ' + insn.disc + ')';
	}
	
	return r;
}

// ************************************************************************
// 
// ************************************************************************
function sub_clear(el)
{
	while (el.firstChild) {
		el.removeChild(el.firstChild);
	}
}

// ************************************************************************
function el(parent, type, text, classes)
{
	let h = document.createElement(type);
	
	if ((text !== undefined) && (text !== null))
		h.textContent = text;
	if ((classes !== undefined) && (classes !== null))
		h.classList = classes;

	if ((parent !== undefined) && (parent !== null))
		parent.appendChild(h);
	
	return h;
}

// ************************************************************************
function anchor(parent, callback)
{
	let h = document.createElement('a');
	
	h.onclick = callback;
	
	parent.appendChild(h);
	
	return h;
}

// ************************************************************************
// 
// ************************************************************************
function nav_build(active)
{
	let nav = el(document.body, 'nav');
	
	let labels = [ 'overview', 'hotspots', 'symbols', 'functions',
		'blocks', '|', 'code', '>', 'reload' ];
	
	let fill = false;
	
	for (let l = 0; l < labels.length; l++) {
		if (labels[l] === '>') {
			fill = true;
			continue;
		}
		
		let etype = (labels[l] === '|') ? 'span' : 'a';
		
		let a = el(nav, etype);
		
		if (labels[l] === active)
			a.classList.add('active');
		if (fill)
			a.classList.add('right');
		
		if (labels[l] === 'reload') {
			a.onclick = function()
				{ window.location.reload(true); } 
		} else if (labels[l] !== '|') {
			a.onclick = function() { mode_set(labels[l]); }
		}

		let lb = labels[l];
		let lbu = lb[0].toUpperCase() + lb.slice(1);
		
		el(a, 'span', lbu);
		
		fill = false;
	}
	
	return nav;
}


// ************************************************************************
// 
// ************************************************************************
function hotspots_list(parent, max)
{
	let table = el(parent, 'table');
	
	let h = el(table, 'tr');
	el(h, 'th', 'samples');
	el(h, 'th', '%');
	el(h, 'th', 'DSO', 'left');
	el(h, 'th', 'offset');
	el(h, 'th', 'block');
	el(h, 'th', 'symbol', 'left');
	el(h, 'th', 'function', 'left');
	
	for (let i = 0; i < meta.hot.length; i++) {
		if (i === max)
			break;
		
		let r = el(table, 'tr');
		
		el(r, 'td', meta.hot[i].hits);
		el(r, 'td',
			(100.0 * meta.hot[i].hits / prog.samples).toFixed(2));
		
		let dso = prog.dso[meta.hot[i].dso];
		el(r, 'td', dso.path, 'left');

		let loc = insn_locate(meta.hot[i].dso, meta.hot[i].ic);
		let insn = insn_info(loc);
		
		el(r, 'td', insn.foffs.toString(16));
		el(r, 'td', insn.block);
		el(r, 'td', insn.sym_str, 'left');
		el(r, 'td', insn.func_str, 'left');

		if (loc.found) {
			r.classList.add('clickable');
			r.onclick = function() { code_open(loc); }
		}
	}
}

function hotspots_build()
{
	let main = el(document.body, 'main');
	
	hotspots_list(main, -1);
}

// ************************************************************************
// 
// ************************************************************************
function symbols_list(parent, max)
{
	let table = el(parent, 'table');
	
	let h = el(table, 'tr');
	el(h, 'th', 'samples');
	el(h, 'th', '%');
	el(h, 'th', 'DSO', 'left');
	el(h, 'th', 'block');
	el(h, 'th', 'symbol', 'left');
	
	for (let i = 0; i < meta.sym.length; i++) {
		if (i === max)
			break;
		
		let r = el(table, 'tr');
		
		el(r, 'td', meta.sym[i].hits);
		el(r, 'td',
			(100.0 * meta.sym[i].hits / prog.samples).toFixed(2));
		
		let dso = prog.dso[meta.sym[i].dso];
		let sym = dso.sym[meta.sym[i].idx];
		let loc = insn_locate_sym(meta.sym[i].dso, meta.sym[i].idx);
		
		el(r, 'td', dso.path, 'left');
		el(r, 'td', loc.block);
		el(r, 'td', sym.name + ((sym.multiple !== 0)
			? '@0x' + sym.addr.toString(16) : ''),
			'left');
		
		if (loc.found) {
			r.classList.add('clickable');
			r.onclick = function() { code_open(loc); }
		}
	}
}

function symbols_build()
{
	let main = el(document.body, 'main');
	
	symbols_list(main, -1);
}

// ************************************************************************
// 
// ************************************************************************
function functions_list(parent, max)
{
	let table = el(parent, 'table');
	
	let h = el(table, 'tr');
	el(h, 'th', 'samples');
	el(h, 'th', '%');
	el(h, 'th', 'DSO', 'left');
	el(h, 'th', 'function', 'left');
	
	for (let i = 0; i < meta.func.length; i++) {
		if (i === max)
			break;
		
		let r = el(table, 'tr');
		
		el(r, 'td', meta.func[i].hits);
		el(r, 'td',
			(100.0 * meta.func[i].hits / prog.samples).toFixed(2));
		
		let dso = prog.dso[meta.func[i].dso];
		let func = dso.func[meta.func[i].idx];

		el(r, 'td', dso.path, 'left');
		el(r, 'td', func.name + '()', 'left');
	}
}

function functions_build()
{
	let main = el(document.body, 'main');
	
	functions_list(main, -1);
}

// ************************************************************************
// 
// ************************************************************************
function blocks_build()
{
	let main = el(document.body, 'main');
	
	for (let i = 0; i < prog.dso.length; i++) {
		let w = el(main, 'h1');
		let y = el(w, 'code', prog.dso[i].path);
		let table = el(main, 'table');

		let h = el(table, 'tr');
		el(h, 'th', 'block');
		el(h, 'th', 'start-offset');
		el(h, 'th', 'end-offset');
		el(h, 'th', 'length');
		el(h, 'th', 'start-insn');
		el(h, 'th', 'end-insn');
		el(h, 'th', 'count');
		
		for (let j = 0; j < prog.dso[i].block.length; j++) {
			let r = el(table, 'tr', null, 'clickable');
			
			let block = prog.dso[i].block[j];
			let last = block.insn[block.insn.length - 1];
			let offs0 = block.insn[0].foffs;
			let offs1 = last.foffs + last.bin.length;
			
			el(r, 'td', j);
			el(r, 'td', '0x' + offs0.toString(16));
			el(r, 'td', '0x' + offs1.toString(16));
			el(r, 'td', offs1 - offs0);
			el(r, 'td', block.base);
			el(r, 'td', block.base + block.insn.length);
			el(r, 'td', block.insn.length);
			
			r.onclick = function() {
				code_open({ found: true,
					dso_id: i, block: j, i: 0 });
			}
		}
	}
}

// ************************************************************************
// 
// ************************************************************************
function overview_build()
{
	let main = el(document.body, 'main');
	
	// ****************************************************************
	el(anchor(el(main, 'h1'), function() { mode_set('hotspots'); }),
		'span', 'Hotspots');

	hotspots_list(main, 10);
	
	el(anchor(el(main, 'h1'), function() { mode_set('symbols'); }),
		'span', 'Symbols');
	
	symbols_list(main, 10);

	el(anchor(el(main, 'h1'), function() { mode_set('functions'); }),
		'span', 'Functions');
	
	functions_list(main, 10);

	// ****************************************************************
	el(main, 'h1', 'DSOs');
	
	let dso_table = el(main, 'table');
	
	let dso_h = el(dso_table, 'tr');
	el(dso_h, 'th', 'samples');
	el(dso_h, 'th', '%');
	el(dso_h, 'th', 'path', 'left');
	el(dso_h, 'th', 'insn');
	el(dso_h, 'th', 'blocks');
	
	for (let i = 0; i < prog.dso.length; i++) {
		let r = el(dso_table, 'tr');
		
		el(r, 'td', prog.dso[i].samples);
		el(r, 'td',
			(100.0 * prog.dso[i].samples
			/ prog.samples).toFixed(2));
		el(r, 'td', prog.dso[i].path, 'left');
		el(r, 'td', prog.dso[i].ninsn);
		el(r, 'td', prog.dso[i].block.length);
	}

	// ****************************************************************
	el(main, 'h1', 'Memory maps');

	let map_table = el(main, 'table');
	
	map_h = el(map_table, 'tr');
	el(map_h, 'th', 'pid');
	el(map_h, 'th', 'start');
	el(map_h, 'th', 'length');
	el(map_h, 'th', 'path', 'left');
	el(map_h, 'th', 'offset');
	
	for (let j = 0; j < prog.pmap.length; j++) {
		let r = el(map_table, 'tr');
		
		el(r, 'td', prog.pmap[j].pid);
		el(r, 'td', '0x' + prog.pmap[j].start.toString(16));
		el(r, 'td', '0x' + prog.pmap[j].length.toString(16));
		el(r, 'td', prog.pmap[j].path, 'left');
		el(r, 'td', '0x' + prog.pmap[j].offset.toString(16));
	}

}

// ************************************************************************
// 
// ************************************************************************
function col_build()
{
	let col = el(null, 'div');
	let top = el(el(col, 'div'), 'code', '-');
	let scroller = el(col, 'div', null, 'codeview');
	let table = el(scroller, 'table');
	
	return { col: col, top: top, scroller: scroller, table: table };
}

// ************************************************************************
function colresize_build(main, col1, col2)
{
	let col = el(null, 'div', null, 'resize');
	
	col.onmousedown = function(e0) {
		let x0 = e0.x;
		let w0 = col1.col.offsetWidth;

		col1.col.style.flexBasis = w0 + 'px';
		col1.col.style.flexShrink = 0;
		col1.col.style.flexGrow = 0;
		
		function move(e) {
			let w1 = w0 + (e.x - x0);
			let wmax = main.clientWidth;
			
			if (w1 < 40)
				w1 = 40;
			if (w1 > wmax - 40)
				w1 = wmax - 40;
			
			col1.col.style.flexBasis = w1 + 'px';
			e.preventDefault();
		}
		
		function up(e) {
			document.removeEventListener('mousemove', move);
			document.removeEventListener('mouseup', up);

			let w1 = w0 + (e.x - x0);

			let cs = getComputedStyle(main);
			let wmax = main.clientWidth
				- parseFloat(cs.paddingLeft)
				- parseFloat(cs.paddingRight);
			
			w2 = wmax - w1 - col.offsetWidth;

			col1.col.style.flexBasis = w1 + 'px';
			col1.col.style.flexShrink = 1;
			col1.col.style.flexGrow = 1;
			col2.col.style.flexBasis = w2 + 'px';
			col2.col.style.flexShrink = 1;
			col2.col.style.flexGrow = 1;
		}
		
		document.addEventListener('mousemove', move);
		document.addEventListener('mouseup', up);
	}

	return col;
}

// ************************************************************************
function code_build()
{
	let main = el(null, 'main', null, 'col');
	
	let col1 = col_build();
	let col2 = col_build();
	let resz = colresize_build(main, col1, col2)
	
	col2.bottom = el(col2.col, 'div', '-');
	
	main.appendChild(col1.col);
	main.appendChild(resz);
	main.appendChild(col2.col);
	
	return {
		dso_id: -1,
		block_id: -1,
		main: main,
		icol: col1,
		irow: [],
		isel_loc: { found: false },
		scol: col2,
		srow: [],
		file_id: -1
	};
}

// ************************************************************************
function code_link(pane, parent, type, cur_loc, i, show_target, hover, suffix)
{
	let target_loc = insn_locate(cur_loc.dso_id, i);
	
	if (!target_loc.found) {
		el(parent, type, (show_target) ? '-' : '');
		return target_loc;
	}

	let text = '';
	
	if (target_loc.block !== cur_loc.block) {
		text += '[\u2192]';
	} else if (target_loc.i < cur_loc.i) {
		text += '[\u2191]';
	} else if (target_loc.i > cur_loc.i) {
		text += '[\u2193]';
	} else {
		text += '[\u2190]';
	}
	
	if (show_target) {
		let info = insn_info(target_loc);
		text += ' ' + info.sym_str;
	}
	
	text += suffix;

	let target_button = el(parent, 'td', text, 'goto');

	target_button.onclick = function(e) {
		code_insn_load(pane, target_loc);
		code_insn_select(pane, target_loc);
		code_insn_goto(pane, target_loc, 'nearest');
		e.stopPropagation();
	};
	
	if (hover) {
		target_button.onmouseenter = function() {
			code_insn_mod(pane, target_loc,
				true, 'insn-hover-target', false);
		}
	
		target_button.onmouseleave = function() {
			code_insn_mod(pane, target_loc,
				false, 'insn-hover-target', false);
		}
	}

	return target_loc;
}

// ************************************************************************
function code_insn_load(pane, loc)
{
	if ((loc.dso_id === pane.dso_id) && (loc.block === pane.block_id))
		return;
	
	pane.isel_loc = { found: false };

	let dso = prog.dso[loc.dso_id];
	let block = dso.block[loc.block];
	let insn = block.insn;
	
	pane.icol.top.textContent = dso.path
		+ ' - block ' + loc.block;
	
	sub_clear(pane.icol.table);
	
	let table = pane.icol.table;
	sub_clear(table);
	
	// compute max hits
	let hits_max = 0;
	for (let k = 0; k < insn.length; k++) {
		if (insn[k].hits > hits_max)
			hits_max = insn[k].hits;
	}

	// build rows
	pane.irow = [ ];
	
	let cur_sym_id = -1;
	let cur_sym_str = '';
	let cur_sym_foffs = 0;
	
	for (let i = 0; i < insn.length; i++) {
		let this_loc = {
			found: true,
			dso_id: loc.dso_id,
			block: loc.block,
			i: i
		};
		
		// label
		if (insn[i].sym_id !== cur_sym_id) {
			cur_sym_id = insn[i].sym_id;
			if (cur_sym_id === -1) {
				cur_sym_str = '';
				cur_sym_foffs = 0;
			} else {
				cur_sym_str = dso.sym[cur_sym_id].name;
				cur_sym_foffs = dso.sym[cur_sym_id].foffs;
			}
			
			let lr = el(table, 'tr');
			
			el(lr, 'td');
			el(lr, 'td');
			lc = el(lr, 'td', cur_sym_str + ':', 'sym');
			lc.colSpan = 2;
			
			if (cur_sym_foffs !== insn[i].foffs) {
				let er = el(table, 'tr');
				el(er, 'td');
				el(er, 'td');
				el(er, 'td');
				el(er, 'td', '[... +0x'
					+ (insn[i].foffs - cur_sym_foffs)
						.toString(16)
					+ ' ...]', 'code sym-offset');
			}
		}

		// row
		let r = el(table, 'tr', null, 'insn');
		
		// hits
		let hits = insn[i].hits;
		
		if (hits > 0) {
			el(r, 'td', (100.0 * hits / prog.samples).toFixed(2),
				'hits');
		} else if (insn[i].flags & INSN_HOTSPOT) {
			el(r, 'td', '|', 'hits');
		} else {
			el(r, 'td');
		}
		
		// bar
		let bar_cell = el(r, 'td', null, 'left');
		
		if (hits > 0) {
			let bar = el(bar_cell, 'span', null, 'bar');
			bar.style.width =
				(2.0 * hits / hits_max) + 'em';
			bar.style.height = '0.75em';
		}
		
		// symbol offset
		if ((cur_sym_id !== -1) && (insn[i].flags & INSN_TARGET)) {
			el(r, 'td', '+0x' +
				(insn[i].foffs - cur_sym_foffs).toString(16)
				+ ':', 'sym-offset');
		} else {
			el(r, 'td');
		}
		
		// disasm
		el(r, 'td', insn[i].disasm, 'code');
		
		// target
		let target_loc = code_link(pane, r, 'td', this_loc,
			insn[i].target_insn, false, false, '');
		
		// branch insn
		let c1t = '';
		let c2t = '';
		let frac_bt = '';
		let frac_mt = '';
		let frac_mb = '';
		let frac_lt = '';
		
		if (insn[i].throughs > 0) {
			frac_bt = (100.0 * insn[i].branches / insn[i].throughs)
				.toFixed(2) + '%';
			frac_mt = (100.0 * insn[i].misses / insn[i].throughs)
				.toFixed(2) + '%';
			frac_lt = (100.0 * insn[i].landings / insn[i].throughs)
				.toFixed(2) + '%';
		}
		
		if (insn[i].branches > 0) {
			frac_mb = (100.0 * insn[i].misses / insn[i].branches)
				.toFixed(2) + '%';
			c1t = frac_bt + 't';
			c2t = frac_mb + 'm';
		}
		
		el(r, 'td', c1t);
		el(r, 'td', c2t);
		
		// details
		let dd = el(null, 'div');

		let dt = el(dd, 'table');
		
		let r1 = el(dt, 'tr');
		el(r1, 'td', '* throughs:');
		el(r1, 'td', insn[i].throughs);
		let r2 = el(dt, 'tr');
		el(r2, 'td', '\u2ba1 branches:');
		el(r2, 'td', insn[i].branches);
		el(r2, 'td', frac_bt);
		let r3 = el(dt, 'tr');
		el(r3, 'td', '\u2ba1 misses:');
		el(r3, 'td', insn[i].misses);
		el(r3, 'td', frac_mb);
		let r4 = el(dt, 'tr');
		el(r4, 'td', '\u2ba1 landings:');
		el(r4, 'td', insn[i].landings);
		el(r4, 'td', frac_lt);
		
		let dt2 = el(dd, 'table');
		
		let r5 = el(dt2, 'tr');
		el(r5, 'td', 'landing');
		el(r5, 'td', 'source:');
		code_link(pane, r5, 'td', this_loc, insn[i].source,
			true, true,
			(insn[i].flags & INSN_SOURCES_MORE)
			? ' (+ more)' : '');
		
		for (let j = 0; j < insn[i].span.length; j++) {
			let r6 = el(dt2, 'tr');
			el(r6, 'td', 'span #' + j);
			el(r6, 'td', 'start:');
			code_link(pane, r6, 'td', this_loc,
				insn[i].span[j].start_i, true, true, '');
			
			let cycles = insn[i].span[j].cycles;
			let count = insn[i].span[j].count;
			
			let r7 = el(dt2, 'tr');
			el(r7, 'td');
			el(r7, 'td', 'cycles:');
			el(r7, 'td', cycles
				+ ', average: ' + (cycles / count).toFixed(1));

			let r8 = el(dt2, 'tr');
			el(r8, 'td');
			el(r8, 'td', 'count:');
			el(r8, 'td', count + ' ('
				+ (100.0 * count / insn[i].branches).toFixed(2)
				+ '%)');
		}

		if (insn[i].flags & INSN_SPANS_MORE) {
			let r6 = el(dt2, 'tr');
			el(r6, 'td');
			el(r6, 'td');
			el(r6, 'td', '(+ more spans)');
		}
		
		/*let r6 = el(dt2, 'tr');
		el(r6, 'td', 'addr:');
		el(r6, 'td', '0x');
		el(r6, 'td', insn[i].addr.toString(16));*/

		// interaction
		r.onclick = function() {
			code_insn_select(pane, this_loc, true);
		}
		
		r.onmouseenter = function() {
			code_insn_mod(pane, this_loc,
				true, 'insn-hover', true);
			code_insn_mod(pane, target_loc,
				true, 'insn-hover-target', false);
		}
	
		r.onmouseleave = function() {
			code_insn_mod(pane, this_loc,
				false, 'insn-hover', true);
			code_insn_mod(pane, target_loc,
				false, 'insn-hover-target', false);
		}

		// store DOM elements
		pane.irow[i] = {
			row: r,
			target_loc: target_loc,
			details: dd,
		};
	}
	
	pane.dso_id = loc.dso_id;
	pane.block_id = loc.block;
}

// ************************************************************************
function code_insn_mod(pane, loc, enter, modif, apply_source)
{
	if ((!loc.found) || (loc.dso_id !== pane.dso_id)
	||  (loc.block !== pane.block_id) || (loc.i === -1))
		return;
	
	let classes = pane.irow[loc.i].row.classList;
	
	if (enter)
		classes.add(modif);
	else
		classes.remove(modif);
	
	if (apply_source) {
		let insn = prog.dso[loc.dso_id].block[loc.block].insn;
		let file_id = insn[loc.i].file_id;
		
		if ((file_id !== -1) && (file_id === pane.file_id)) {
			let l = insn[loc.i].line;
			let lclasses = pane.srow[l].row.classList;
			
			if (enter)
				lclasses.add(modif);
			else
				lclasses.remove(modif);
		}
	}
}

// ************************************************************************
function code_insn_select(pane, loc, toggle)
{
	let insn = prog.dso[loc.dso_id].block[loc.block].insn[loc.i];
	
	if (insn.file_id !== pane.file_id) {
		code_source_load(pane, loc.dso_id, insn.file_id);
		code_source_goto(pane, loc.dso_id,
			insn.file_id, insn.line);
	} else {
		code_source_goto(pane, loc.dso_id,
			insn.file_id, insn.line, 'nearest');
	}

	if (pane.isel_loc.found) {
		code_insn_mod(pane, pane.isel_loc, false, 'insn-select', true);
		code_insn_mod(pane, pane.irow[pane.isel_loc.i].target_loc,
			false, 'insn-select-target', false);
	}
	
	if ((toggle !== undefined) && (toggle)
	&&  (pane.isel_loc.found) && (loc.dso_id === pane.isel_loc.dso_id)
	&&  (loc.block === pane.isel_loc.block)
	&&  (loc.i === pane.isel_loc.i)) {
		pane.isel_loc = { found: false };
	} else {
		code_insn_mod(pane, loc, true, 'insn-select', true);
		code_insn_mod(pane, pane.irow[loc.i].target_loc,
			true, 'insn-select-target', false);
		
		let details = pane.irow[loc.i].details;
		pane.scol.col.removeChild(pane.scol.bottom);
		pane.scol.col.appendChild(details);
		pane.scol.bottom = details;

		pane.isel_loc = loc;
	}
}

// ************************************************************************
function code_insn_goto(pane, loc, mode)
{
	let opt = {
		behavior: 'auto',
		block: 'center',
		inline: 'center'
	};
	
	if (mode !== undefined) {
		opt.block = mode;
		opt.inline = mode;
	}

	pane.irow[loc.i].row.scrollIntoView(opt);
}

// ************************************************************************
function code_source_load(pane, dso_id, file_id)
{
	for (let j = 0; j < pane.irow.length; j++) {
		pane.irow[j].row.classList.remove('src-hover-insn');
	}

	if ((dso_id === pane.dso_id) && (file_id === pane.file_id))
		return;

	if ((dso_id === -1) || (file_id === -1)) {
		pane.scol.top.textContent = '-';
		sub_clear(pane.scol.table);
		pane.file_id = file_id;
		pane.srow = [];
		return;
	}

	let dso = prog.dso[dso_id];
	let file = dso.file[file_id];
	let line = file.line;
	
	pane.scol.top.textContent = file.name;

	let table = pane.scol.table;
	sub_clear(table);
	
	for (let l = 1; l < line.length; l++) {
		let r = el(table, 'tr', null, 'src');
		
		// line number
		el(r, 'td', l, 'line');
		
		// code
		lc = el(r, 'td', null, 'code');
		
		lc.innerHTML = line[l];

		// interaction
		r.onclick = function() {
			if (pane.srow[l].insn.length >= 1) {
				let i = pane.srow[l].insn[0];
				let loc = {
					found: true,
					dso_id: dso_id,
					block: pane.block_id,
					i: i
				};
				
				code_insn_goto(pane, loc, 'nearest');
			}
		}

		r.onmouseenter = function() {
			for (let k in pane.srow[l].insn) {
				let i = pane.srow[l].insn[k];
				pane.irow[i].row.classList
					.add('src-hover');
			}
		}

		r.onmouseleave = function() {
			for (let k in pane.srow[l].insn) {
				let i = pane.srow[l].insn[k];
				pane.irow[i].row.classList
					.remove('src-hover');
			}
		}
		
		// store DOM elements
		pane.srow[l] = {
			row: r,
			insn: []
		};
	}
	
	let block = dso.block[pane.block_id];
	let insn = block.insn;
	for (let i = 0; i < insn.length; i++) {
		let tl = insn[i].line;
		
		if ((insn[i].file_id === file_id)
		&&  (tl >= 1) && (tl < line.length)) {
			pane.srow[tl].insn.push(i);
		}
	}
	
	pane.file_id = file_id;
}

// ************************************************************************
function code_source_goto(pane, dso_id, file_id, line, mode)
{
	if ((dso_id === -1) || (file_id === -1) || (line < 1))
		return;
	
	let opt = {
		behavior: 'auto',
		block: 'center',
		inline: 'center'
	};
	
	if (mode !== undefined) {
		opt.block = mode;
		opt.inline = mode;
	}

	pane.srow[line].row.scrollIntoView(opt);
}

// ************************************************************************
function code_state_save(pane)
{
	pane.state = {
		ix: pane.icol.scroller.scrollLeft,
		iy: pane.icol.scroller.scrollTop,
		sx: pane.scol.scroller.scrollLeft,
		sy: pane.scol.scroller.scrollTop,
	}

	if ('key_handler' in pane)
		document.removeEventListener('keydown', pane.key_handler);
}

function code_state_restore(pane)
{
	if ('state' in pane) {
		pane.icol.scroller.scrollLeft = pane.state.ix;
		pane.icol.scroller.scrollTop = pane.state.iy;
		pane.scol.scroller.scrollLeft = pane.state.sx;
		pane.scol.scroller.scrollTop = pane.state.sy;
	}

	pane.key_handler = function(e)
	{
		if ((!pane.isel_loc.found)
		||  (pane.isel_loc.dso_id === -1)
		||  (pane.isel_loc.block === '')
		||  (pane.isel_loc.i === -1))
			return;
		
		let tloc = {
			found: true,
			dso_id: pane.isel_loc.dso_id,
			block: pane.isel_loc.block,
			i: pane.isel_loc.i
		};
		
		let ilen = pane.irow.length;
		let managed = true;
		
		if (e.code === 'ArrowUp') {
			tloc.i--;
		} else if (e.code === 'ArrowDown') {
			tloc.i++;
		} else if (e.code === 'PageUp') {
			tloc.i -= 10;
		} else if (e.code === 'PageDown') {
			tloc.i += 10;
		} else if (e.code === 'Home') {
			tloc.i = 0;
		} else if (e.code === 'End') {
			tloc.i = ilen - 1;
		} else {
			managed = false;
		}
		
		if (managed) {
			if (tloc.i < 0)
				tloc.i = 0;
			if (tloc.i >= ilen)
				tloc.i = ilen - 1;
	
			code_insn_select(pane, tloc);
			code_insn_goto(pane, tloc, 'nearest');
			e.preventDefault();
		}
	}
	
	document.addEventListener('keydown', pane.key_handler);
}
				  

// ************************************************************************
// 
// ************************************************************************
var global_code = {};

var ui_state = {
	cur_mode: '',
	mode: []
}

function code_prebuild()
{
	global_code = code_build();
}

function code_restore()
{
	sub_clear(document.body);
	document.body.classList = 'full';
	nav_build('code');
	
	document.body.appendChild(global_code.main);
	
	code_state_restore(global_code);
	ui_state.cur_mode = 'code';
}

function code_save()
{
	code_state_save(global_code);
}

function code_open(loc)
{
	code_insn_load(global_code, loc);
	code_restore();
	code_insn_select(global_code, loc);
	code_insn_goto(global_code, loc);
}

// ************************************************************************
// 
// ************************************************************************
function mode_set(mode)
{
	if (ui_state.cur_mode === 'code') {
		code_save();
	}

	ui_state.cur_mode = mode;
	
	if (mode === 'code') {
		code_restore()
		return;
	}

	sub_clear(document.body);
	document.body.classList = '';
	nav_build(mode);
	
	switch (mode) {
	case 'overview':
		overview_build();
		break;
	case 'hotspots':
		hotspots_build();
		break;
	case 'symbols':
		symbols_build();
		break;
	case 'functions':
		functions_build();
		break;
	case 'blocks':
		blocks_build();
		break;
	}
}

// ************************************************************************
// 
// ************************************************************************
window.onload = function()
{
	code_prebuild();
	mode_set('overview');
};

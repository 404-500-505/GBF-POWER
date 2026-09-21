"""Client-only drawn controls. No native Button/Checkbutton/Combobox styling.

Finite 140 ms transitions run only on interaction, never while idle. Tk variables
remain the source of truth; the networking and authorization layer is untouched.
"""
import time
import ctypes
import tkinter as tk
from tkinter import font as tkfont
from PIL import Image, ImageDraw, ImageTk

FONT = ('Microsoft YaHei UI', 10)
RADIUS = 12


def monitor_work_area(widget):
    """Anchor monitor work area, including negative coordinates and taskbars."""
    try:
        from ctypes import wintypes
        class MonitorInfo(ctypes.Structure):
            _fields_=[('cbSize',wintypes.DWORD),('rcMonitor',wintypes.RECT),
                      ('rcWork',wintypes.RECT),('dwFlags',wintypes.DWORD)]
        user=ctypes.windll.user32
        user.MonitorFromWindow.argtypes=[wintypes.HWND,wintypes.DWORD]
        user.MonitorFromWindow.restype=wintypes.HANDLE
        user.GetMonitorInfoW.argtypes=[wintypes.HANDLE,ctypes.POINTER(MonitorInfo)]
        user.GetMonitorInfoW.restype=wintypes.BOOL
        info=MonitorInfo(); info.cbSize=ctypes.sizeof(info)
        monitor=user.MonitorFromWindow(widget.winfo_id(),2)
        if user.GetMonitorInfoW(monitor,ctypes.byref(info)):
            r=info.rcWork
            return r.left,r.top,r.right,r.bottom
    except (AttributeError,OSError):
        pass
    return 0,0,widget.winfo_screenwidth(),widget.winfo_screenheight()


def popup_position(anchor,size,work):
    ax,ay,aw,ah=anchor; width,height=size; left,top,right,bottom=work
    x=max(left,min(ax,right-width))
    below=ay+ah+4
    y=below if below+height<=bottom else ay-height-4
    return x,max(top,min(y,bottom-height))


def blend(a, b, amount):
    return '#' + ''.join(f'{round(int(a[i:i+2],16)*(1-amount)+int(b[i:i+2],16)*amount):02x}'
                         for i in (1, 3, 5))


class GlassButton(tk.Canvas):
    def __init__(self, parent, text='', command=None, palette=None, primary=False,
                 width=0, font=FONT, **kw):
        self.palette = palette
        self.primary = primary
        self.command = command
        self.text = text
        self.control_state = kw.pop('state', 'normal')
        self.hovered = self.pressed = self.focused = False
        self.animation_id = None
        self.level = 0.
        self.selection = 0.
        self.scale = float(parent.tk.call('tk', 'scaling')) / (96 / 72)
        self.font = tkfont.Font(root=parent, font=font)
        self.width_chars = width
        super().__init__(parent, bd=0, highlightthickness=0, takefocus=1,
                         cursor='hand2', background=parent.cget('bg'), **kw)
        self.bind('<Configure>', lambda _: self.paint())
        self.bind('<Enter>', lambda _: self._hover(True))
        self.bind('<Leave>', lambda _: self._hover(False))
        self.bind('<ButtonPress-1>', self._press)
        self.bind('<ButtonRelease-1>', self._release)
        self.bind('<FocusIn>', lambda _: self._focus(True))
        self.bind('<FocusOut>', lambda _: self._focus(False))
        self.bind('<KeyPress-space>', self._key_down)
        self.bind('<KeyRelease-space>', self._key_up)
        self.bind('<Return>', lambda _: self.invoke())
        self.bind('<Destroy>', self._destroyed, add='+')
        self._measure()

    def _measure(self):
        width = max(self.font.measure(self.text), self.font.measure('0')*self.width_chars)
        tk.Canvas.configure(self, width=width+round(30*self.scale),
                            height=max(self.font.metrics('linespace')+round(16*self.scale),round(38*self.scale)))

    def cget(self, key):
        if key == 'text': return self.text
        if key == 'state': return self.control_state
        return super().cget(key)

    def configure(self, cnf=None, **kw):
        if cnf: kw.update(cnf)
        if not kw: return super().configure()
        measure = False
        changed = False
        if 'text' in kw:
            text = kw.pop('text'); measure = text != self.text; self.text = text
        if 'command' in kw: self.command = kw.pop('command')
        if 'state' in kw:
            state=kw.pop('state')
            changed=state!=self.control_state
            self.control_state = state
            if self.control_state == 'disabled':
                self.pressed = self.hovered = False
                if hasattr(self, 'close_popup'): self.close_popup()
            tk.Canvas.configure(self, takefocus=int(self.control_state != 'disabled'),
                                cursor='' if self.control_state == 'disabled' else 'hand2')
        if kw: super().configure(**kw); changed=True
        if measure: self._measure()
        if measure or changed: self.paint()

    config = configure

    def set_palette(self, palette):
        self.palette = palette
        self._cancel_animation()
        self.level = 0.
        self.selection = float(self.selected())
        self.hovered = self.pressed = False
        self.paint()

    def _cancel_animation(self):
        if self.animation_id is not None:
            self.after_cancel(self.animation_id)
            self.animation_id = None

    def _destroyed(self, event):
        if event.widget is self:
            self._cancel_animation()

    def _hover(self, value):
        self.hovered = value
        self.animate()

    def _focus(self, value):
        self.focused = value
        if not value: self.pressed = False
        self.animate()

    def _press(self, event):
        if self.control_state == 'disabled': return 'break'
        self.focus_set(); self.pressed = True; self.animate()
        return 'break'

    def _release(self, event):
        was_pressed = self.pressed
        self.pressed = False; self.animate()
        if was_pressed and 0 <= event.x < self.winfo_width() and 0 <= event.y < self.winfo_height():
            self.invoke()
        return 'break'

    def _key_down(self, _):
        if self.control_state != 'disabled':
            self.pressed = True; self.animate()
        return 'break'

    def _key_up(self, _):
        if self.pressed:
            self.pressed = False; self.animate(); self.invoke()
        return 'break'

    def invoke(self):
        if self.control_state != 'disabled' and self.command:
            return self.command()

    def selected(self):
        return False

    def animate(self):
        self._cancel_animation()
        origin, initial = self.level, self.selection
        target = (1. if self.pressed else .55 if self.hovered else 0.) if self.control_state != 'disabled' else 0.
        selected = float(self.selected())
        start = time.monotonic()
        def tick():
            self.animation_id = None
            progress = min(1., (time.monotonic()-start)/.14)
            eased = 1-(1-progress)**3
            self.level = origin+(target-origin)*eased
            self.selection = initial+(selected-initial)*eased
            self.paint()
            if progress < 1:
                self.animation_id = self.after(16, tick)
        self.animation_id = self.after(16, tick)

    def surface(self):
        width, height = self.winfo_width(), self.winfo_height()
        if width < 3 or height < 3: return None
        bg = self.master.cget('bg')
        tk.Canvas.configure(self, bg=bg)
        image = Image.new('RGB', (width*2, height*2), bg)
        return image, ImageDraw.Draw(image), width, height

    def show_surface(self, image):
        image = image.resize((image.width//2,image.height//2),Image.Resampling.LANCZOS)
        self._surface_image = ImageTk.PhotoImage(image,master=self)
        self.delete('all')
        self.create_image(0,0,image=self._surface_image,anchor='nw')

    def paint(self):
        surface = self.surface()
        if surface is None: return
        image, draw, width, height = surface
        p, s = self.palette, self.scale
        base = p['accent'] if self.primary else p['button']
        ink = (p['bg'] if p['bg'] == '#111924' else p['white']) if self.primary else p['text']
        fill = blend(base, p['text'] if not self.primary else p['white'], self.level*.10)
        if self.control_state == 'disabled':
            fill = blend(base,p['card'],.68); ink = p['muted']
        offset = round(self.level*s)
        radius = round(RADIUS*s*2)
        draw.rounded_rectangle((2,6,(width-1)*2,(height-1)*2),radius,fill=p['shadow'])
        draw.rounded_rectangle((2,2+offset,(width-1)*2,(height-3)*2),radius,fill=fill,
                               outline=p['accent'] if self.focused else p['rim'],width=2)
        if self.focused:
            draw.rounded_rectangle((6,6+offset,(width-3)*2,(height-5)*2),max(1,radius-4),outline=p['accent'],width=2)
        self.show_surface(image)
        self.create_text(width/2,height/2-1+offset/2,text=self.text,font=self.font,fill=ink)


class GlassChoice(GlassButton):
    """Checkbox, switch and mutually exclusive radio share variable semantics."""
    def __init__(self, parent, text, variable, command=None, kind='check', value=None, **kw):
        self.variable, self.kind, self.value = variable, kind, value
        super().__init__(parent,text=text,command=command,**kw)
        self.selection = float(self.selected())
        self.last_selection = self.selected()
        self.trace = variable.trace_add('write', self._variable_changed)

    def _variable_changed(self,*_):
        selected=self.selected()
        if selected!=self.last_selection:
            self.last_selection=selected
            self.animate()

    def _measure(self):
        tk.Canvas.configure(self,width=self.font.measure(self.text)+round((60 if self.kind=='switch' else 40)*self.scale),
                            height=max(round(36*self.scale),self.font.metrics('linespace')+12))

    def selected(self):
        return self.variable.get() == self.value if self.kind == 'radio' else bool(self.variable.get())

    def invoke(self):
        if self.control_state == 'disabled': return
        self.variable.set(self.value if self.kind == 'radio' else not self.variable.get())
        if self.command: return self.command()

    def _destroyed(self, event):
        if event.widget is self and hasattr(self,'trace'):
            self.variable.trace_remove('write',self.trace)
        super()._destroyed(event)

    def paint(self):
        surface = self.surface()
        if surface is None: return
        image, draw, width, height = surface
        p,s = self.palette,self.scale
        y=height; size=round(19*s*2); x=round(5*s*2)
        fill=blend(p['button'],p['accent'],self.selection)
        ink=p['text']
        if self.control_state=='disabled': fill=blend(fill,p['card'],.65); ink=p['muted']
        draw.rounded_rectangle((2,2,width*2-2,height*2-2),round(RADIUS*s*2),
            fill=blend(self.master.cget('bg'),p['hover'],self.level),
            outline=p['accent'] if self.focused else None,width=2)
        if self.kind=='switch':
            track=round(38*s*2)
            draw.rounded_rectangle((x,y-size/2,x+track,y+size/2),size//2,fill=fill,outline=p['line'],width=2)
            knob=size-6; left=x+3+(track-size)*self.selection
            draw.ellipse((left,y-knob/2,left+knob,y+knob/2),fill=p['white'])
            label_x=round(52*s)
        else:
            bounds=(x,y-size/2,x+size,y+size/2)
            if self.kind=='radio':
                draw.ellipse(bounds,fill=p['button'],outline=p['accent'] if self.selected() else p['muted'],width=2)
                inset=size*(.5-.23*self.selection)
                if self.selection>.01: draw.ellipse((x+inset,y-size/2+inset,x+size-inset,y+size/2-inset),fill=p['accent'])
            else:
                draw.rounded_rectangle(bounds,round(5*s*2),fill=fill,outline=p['accent'] if self.selected() else p['muted'],width=2)
                if self.selection>.01:
                    check=blend(fill,p['bg'] if p['bg']=='#111924' else p['white'],self.selection)
                    draw.line((x+size*.23,y,x+size*.44,y+size*.20,x+size*.79,y-size*.23),fill=check,width=max(2,round(2*s*2)))
            label_x=round(33*s)
        self.show_surface(image)
        self.create_text(label_x,height/2,text=self.text,font=self.font,fill=ink,anchor='w')


class GlassSelect(GlassButton):
    def __init__(self,parent,textvariable,values,**kw):
        self.variable=textvariable
        self.values=tuple(values)
        self.popup=None
        kw.setdefault('state','readonly')
        super().__init__(parent,text=textvariable.get(),command=self.open_popup,**kw)
        self.trace=textvariable.trace_add('write',self._changed)
        self.bind('<Down>',lambda _: self.open_popup())
        self.bind('<Up>',lambda _: self.open_popup())
        self.bind('<Escape>',lambda _: self.close_popup())

    def _measure(self):
        text_width=max([self.font.measure(v) for v in self.values]+[self.font.measure(self.text)])
        tk.Canvas.configure(self,width=max(text_width,self.width_chars*self.font.measure('0'))+round(56*self.scale),
                            height=max(round(40*self.scale),self.font.metrics('linespace')+16))

    def _changed(self,*_):
        text=self.variable.get()
        if text!=self.text:
            self.text=text; self.paint()

    def get(self): return self.variable.get()

    def choose(self,index):
        self.variable.set(self.values[index])
        self.event_generate('<<ComboboxSelected>>')

    def cget(self,key):
        if key=='values': return self.values
        return super().cget(key)

    def open_popup(self):
        if self.control_state=='disabled' or not self.values: return
        if self.popup: self.close_popup(); return
        active=getattr(self.winfo_toplevel(),'_glass_popup',None)
        if active: active.close()
        self.focus_set()
        index=self.values.index(self.get()) if self.get() in self.values else 0
        self.popup=SelectPopup(self,index)
        self.paint()

    def close_popup(self):
        if self.popup: self.popup.close()

    def set_palette(self,palette):
        self.close_popup(); super().set_palette(palette)

    def _destroyed(self,event):
        if event.widget is self:
            self.close_popup()
            if hasattr(self,'trace'): self.variable.trace_remove('write',self.trace)
        super()._destroyed(event)

    def paint(self):
        super().paint()
        if self.winfo_width()<3: return
        # Replace the centered caption with a leading label and custom chevron.
        for item in self.find_all():
            if self.type(item)=='text': self.delete(item)
        p,s=self.palette,self.scale
        color=p['muted'] if self.control_state=='disabled' else p['text']
        self.create_text(14*s,self.winfo_height()/2-1,text=self.text,anchor='w',font=self.font,fill=color)
        x,y=self.winfo_width()-20*s,self.winfo_height()/2
        direction=-1 if self.popup else 1
        self.create_line(x-4*s,y-2*s*direction,x,y+2*s*direction,x+4*s,y-2*s*direction,
                         fill=color,width=max(1,1.5*s),capstyle='round',joinstyle='round')


class SelectPopup:
    """Drawn rounded option sheet; no ttk popup or native listbox involved."""
    def __init__(self,owner,index):
        self.owner,self.index=owner,index
        self.closed=False
        self.focus_timer=None
        self.top=owner.winfo_toplevel()
        self.owner_geometry=self.top.geometry()
        self.top._glass_popup=self
        self.window=tk.Toplevel(self.top)
        self.window.protocol('WM_DELETE_WINDOW',self.close)
        self.window.bind('<Destroy>',self.window_destroyed,add='+')
        self.window.withdraw(); self.window.overrideredirect(True)
        self.window.transient(self.top)
        self.window.attributes('-topmost',bool(self.top.attributes('-topmost')))
        self.canvas=tk.Canvas(self.window,bd=0,highlightthickness=0,takefocus=1,bg=owner.palette['bg'])
        self.canvas.pack(fill='both',expand=True)
        self.row_height=max(round(38*owner.scale),owner.font.metrics('linespace')+14)
        self.pad=round(8*owner.scale)
        self.width=max(owner.winfo_width(),max(owner.font.measure(v) for v in owner.values)+round(60*owner.scale))
        self.height=len(owner.values)*self.row_height+self.pad*2
        x,y=popup_position((owner.winfo_rootx(),owner.winfo_rooty(),owner.winfo_width(),owner.winfo_height()),
                          (self.width,self.height),monitor_work_area(owner))
        # '+-x' encodes absolute negative coordinates in Tk, unlike '-x' which
        # positions relative to the right/bottom edge of the virtual root.
        self.window.geometry(f'{self.width}x{self.height}+{x}+{y}')
        self.canvas.bind('<Motion>',self.motion)
        self.canvas.bind('<ButtonPress-1>',self.click)
        self.window.bind('<ButtonPress-1>',self.click)
        self.canvas.bind('<Escape>',lambda _: self.close())
        self.canvas.bind('<Down>',lambda _: self.move(1))
        self.canvas.bind('<Up>',lambda _: self.move(-1))
        self.canvas.bind('<Home>',lambda _: self.move(-len(owner.values)))
        self.canvas.bind('<End>',lambda _: self.move(len(owner.values)))
        self.canvas.bind('<Return>',lambda _: self.commit())
        self.canvas.bind('<space>',lambda _: self.commit())
        self.canvas.bind('<Tab>',lambda _: self.tab(False))
        self.canvas.bind('<Shift-Tab>',lambda _: self.tab(True))
        self.canvas.bind('<MouseWheel>',lambda e: self.move(-1 if e.delta>0 else 1))
        self.window.bind('<FocusOut>',self.focus_out)
        self.top_binding=self.top.bind('<Configure>',self.owner_moved,add='+')
        self.unmap_binding=self.top.bind('<Unmap>',self.owner_hidden,add='+')
        self.draw()
        self.window.deiconify(); self.window.update_idletasks()
        # A topmost owner and an override-redirect popup occupy the same Z band
        # on Windows; mapping alone can leave the owner above the popup.
        self.window.lift(self.top)
        self.canvas.focus_force(); self.window.grab_set()

    def draw(self):
        p,s=self.owner.palette,self.owner.scale
        image=Image.new('RGB',(self.width*2,self.height*2),p['bg'])
        d=ImageDraw.Draw(image)
        d.rounded_rectangle((2,4,self.width*2-2,self.height*2-2),round(16*s*2),fill=p['shadow'])
        d.rounded_rectangle((2,2,self.width*2-4,self.height*2-6),round(14*s*2),fill=p['card'],outline=p['rim'],width=2)
        y=self.pad+self.index*self.row_height
        d.rounded_rectangle((self.pad*2,y*2,(self.width-self.pad)*2,(y+self.row_height)*2),round(9*s*2),fill=p['hover'])
        self.image=ImageTk.PhotoImage(image.resize((self.width,self.height),Image.Resampling.LANCZOS),master=self.canvas)
        self.canvas.delete('all'); self.canvas.create_image(0,0,image=self.image,anchor='nw')
        for i,value in enumerate(self.owner.values):
            cy=self.pad+(i+.5)*self.row_height
            self.canvas.create_text(self.pad+12*s,cy,text=value,anchor='w',font=self.owner.font,fill=p['text'])
            if value==self.owner.get():
                x=self.width-self.pad-18*s
                self.canvas.create_line(x-5*s,cy,x-1*s,cy+4*s,x+6*s,cy-4*s,
                                        fill=p['accent'],width=2*s,capstyle='round',joinstyle='round')

    def move(self,delta):
        self.index=max(0,min(len(self.owner.values)-1,self.index+delta)); self.draw()
        return 'break'

    def motion(self,event):
        index=(event.y-self.pad)//self.row_height
        if 0<=index<len(self.owner.values) and self.pad<=event.x<self.width-self.pad and index!=self.index:
            self.index=index; self.draw()

    def click(self,event):
        # The local grab also routes outside clicks here.
        x,y=event.x_root-self.window.winfo_rootx(),event.y_root-self.window.winfo_rooty()
        if not (0<=x<self.width and 0<=y<self.height): self.close(); return 'break'
        index=(y-self.pad)//self.row_height
        if 0<=index<len(self.owner.values): self.index=index; self.commit()
        return 'break'

    def commit(self):
        owner=self.owner; index=self.index
        self.close()
        if owner.control_state!='disabled':
            owner.choose(index)
        return 'break'

    def tab(self,backwards):
        target=self.owner.tk_focusPrev() if backwards else self.owner.tk_focusNext()
        self.close(); target.focus_set()
        return 'break'

    def owner_moved(self,event):
        # Raising a transient window also generates Configure on Windows. Only
        # actual movement/resize invalidates the anchor, not a stacking change.
        if event.widget is self.top and self.top.geometry()!=self.owner_geometry: self.close()

    def owner_hidden(self,event):
        if event.widget is self.top: self.close()

    def focus_out(self,_):
        if not self.closed and self.focus_timer is None:
            self.focus_timer=self.window.after_idle(self.check_focus)

    def check_focus(self):
        self.focus_timer=None
        if self.closed: return
        focus=self.window.focus_get()
        if focus is None or focus.winfo_toplevel()!=self.window: self.close(restore=False)

    def window_destroyed(self,event):
        if event.widget is self.window:
            self.close(restore=False,destroy=False)

    def close(self,restore=True,destroy=True):
        if self.closed: return
        self.closed=True
        if self.focus_timer: self.window.after_cancel(self.focus_timer)
        self.top.unbind('<Configure>',self.top_binding)
        self.top.unbind('<Unmap>',self.unmap_binding)
        if self.window.winfo_exists():
            if self.top.grab_current()==self.window: self.window.grab_release()
            if destroy: self.window.destroy()
        self.owner.popup=None
        self.top._glass_popup=None
        if self.owner.winfo_exists():
            if restore: self.owner.focus_set()
            self.owner.paint()


class GlassMenu:
    """Small command menu using the same custom option sheet as the selectors."""
    def __init__(self,anchor,palette):
        self.anchor,self.palette=anchor,palette
        self.entries=[]
        self.popup=None
        self.control_state='normal'

    def __getattr__(self,name):
        return getattr(self.anchor,name)

    @property
    def values(self):
        return tuple(e['label'] for e in self.entries if e['type']=='command')

    def get(self): return ''

    def add_command(self,label,command):
        self.entries.append(dict(label=label,command=command,type='command'))

    def add_separator(self):
        self.entries.append(dict(type='separator'))

    def index(self,value):
        return len(self.entries)-1 if value=='end' else int(value)

    def entrycget(self,index,key): return self.entries[index][key]

    def type(self,index): return self.entries[index]['type']

    def choose(self,index):
        [e for e in self.entries if e['type']=='command'][index]['command']()

    def tk_popup(self,*_):
        active=getattr(self.anchor.winfo_toplevel(),'_glass_popup',None)
        if active: active.close()
        self.popup=SelectPopup(self,0)

    def destroy(self):
        if self.popup: self.popup.close()

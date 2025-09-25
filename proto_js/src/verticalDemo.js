// verticalDemo.js - integrate VerticalController with crate prototype (lightweight)
import {VerticalController} from './verticalController.js';

function runDemo(frames=50) {
  const vc = new VerticalController(3);
  for (let i=0;i<frames;i++) {
    vc.tick(ev => {
      console.log(`[emit] frame=${i} scaled=${ev.scaled} step=${ev.step} scale=${ev.scale}`);
    });
    const {y, gate} = vc.sampleEmitterY(2000);
    if (i % 8 === 0) {
      console.log(`[f${i}] y=${y} gate=${gate} phase=${vc.phaseToggleB} progress=${vc.progress}`);
    }
  }
}

if (typeof module !== 'undefined' && require.main === module) {
  runDemo();
}

export { runDemo };
